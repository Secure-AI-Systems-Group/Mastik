/*
 * Copyright 2016 CSIRO
 *
 * This file is part of Mastik.
 *
 * Mastik is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Mastik is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Mastik.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <strings.h>
#include <sys/mman.h>
#ifdef __APPLE__
#include <mach/vm_statistics.h>
#endif

#include "vlist.h"
#include "l3.h"
#include "timestats.h"
#include "low.h"

#define CHECKTIMES 16

/*
 * Intel documentation still mentiones one slice per core, but
 * experience shows that at least some Skylake models have two
 * smaller slices per core. 
 * When probing the cache, we can use the smaller size - this will
 * increase the probe time but for huge pages, where we use
 * the slice size, the probe is fast and the increase is not too
 * significant.
 * When using the PTE maps, we need to know the correct size and
 * the correct number of slices.  This means that, currently and
 * without user input, PTE is not guaranteed to work.
 * So, on a practical note, L3_GROUPSIZE_FOR_HUGEPAGES is the
 * smallest slice size we have seen; L3_SETS_PER_SLICE is the
 * default for the more common size.  If we learn how to probe
 * the slice size we can get rid of this mess.
 */
#define L3_SETS_PER_SLICE 2048
#define L3_GROUPSIZE_FOR_HUGEPAGES 1024

// The number of cache sets in each page
#define L3_SETS_PER_PAGE 64

#define L3_CACHELINE 64

#define LNEXT(t) (*(void **)(t))
#define OFFSET(p, o) ((void *)((uintptr_t)(p) + (o)))
#define NEXTPTR(p) (OFFSET((p), sizeof(void *)))

#define IS_MONITORED(monitored, setno) ((monitored)[(setno)>>5] & (1 << ((setno)&0x1f)))
#define SET_MONITORED(monitored, setno) ((monitored)[(setno)>>5] |= (1 << ((setno)&0x1f)))
#define UNSET_MONITORED(monitored, setno) ((monitored)[(setno)>>5] &= ~(1 << ((setno)&0x1f)))

#ifdef MAP_HUGETLB
#define HUGEPAGES MAP_HUGETLB
#endif
#ifdef VM_FLAGS_SUPERPAGE_SIZE_2MB
#define HUGEPAGES VM_FLAGS_SUPERPAGE_SIZE_2MB
#endif

#ifdef HUGEPAGES
#define HUGEPAGEBITS 21
#define HUGEPAGESIZE (1<<HUGEPAGEBITS)
#define HUGEPAGEMASK (HUGEPAGESIZE - 1)
#endif


#define SLICE_MASK_0 0x1b5f575440UL
#define SLICE_MASK_1 0x2eb5faa880UL
#define SLICE_MASK_2 0x3cccc93100UL

struct l3pp {
  struct l3info l3info;
  union cpuid cpuidInfo;

  // To reduce probe time we group sets in cases that we know that a group of consecutive cache lines will
  // always map to equivalent sets. In the absence of user input (yet to be implemented) the decision is:
  // Non linear mappings - 1 set per group (to be implemeneted)
  // Huge pages - L3_SETS_PER_SLICE sets per group (to be impolemented)
  // Otherwise - L3_SETS_PER_PAGE sets per group.
  int ngroups;
  int groupsize;
  vlist_t *groups;
  void *buffer;
  uint32_t *monitoredbitmap;
  int *monitoredset;
  int nmonitored;
  void **monitoredhead;
};


static int parity(uint64_t v) {
  v ^= v >> 1;
  v ^= v >> 2;
  v = (v & 0x1111111111111111UL) * 0x1111111111111111UL;
  return (v >> 60) & 1;
}


static int addr2slice_linear(uintptr_t addr, int slices) {
  int bit0 = parity(addr & SLICE_MASK_0);
  int bit1 = parity(addr & SLICE_MASK_1);
  int bit2 = parity(addr & SLICE_MASK_2);
  return ((bit2 << 2) | (bit1 << 1) | bit0) & (slices - 1);
}

static uintptr_t getphysaddr(void *p) {
#ifdef __linux__
  static int fd = -1;

  if (fd < 0) {
    fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0)
      return 0;
  }
  uint64_t buf;
  memaccess(p);
  uintptr_t intp = (uintptr_t)p;
  int r = pread(fd, &buf, sizeof(buf), ((uintptr_t)p)/4096 * sizeof(buf));

  return (buf & ((1ULL << 54) - 1)) << 12 | ((uintptr_t)p & 0x3ff);
#else
  return 0;
#endif
}


static int loadL3cpuidInfo(l3pp_t l3) {

  for (int i = 0; ; i++) {
    l3->cpuidInfo.regs.eax = CPUID_CACHEINFO;
    l3->cpuidInfo.regs.ecx = i;
    cpuid(&l3->cpuidInfo);
    if (l3->cpuidInfo.cacheInfo.type == 0)
      return 0;
    if (l3->cpuidInfo.cacheInfo.level == 3)
      return 1;
  }
}

static void fillL3Info(l3pp_t l3) {
  loadL3cpuidInfo(l3);
  if (l3->l3info.associativity == 0)
    l3->l3info.associativity = l3->cpuidInfo.cacheInfo.associativity + 1;
  if (l3->l3info.slices == 0) {
    if (l3->l3info.setsperslice == 0)
      l3->l3info.setsperslice = L3_SETS_PER_SLICE;
    l3->l3info.slices = (l3->cpuidInfo.cacheInfo.sets + 1)/ l3->l3info.setsperslice;
  }
  if (l3->l3info.setsperslice == 0)
    l3->l3info.setsperslice = (l3->cpuidInfo.cacheInfo.sets + 1)/l3->l3info.slices;
  if (l3->l3info.bufsize == 0) {
    l3->l3info.bufsize = l3->l3info.associativity * l3->l3info.slices * l3->l3info.setsperslice * L3_CACHELINE * 2;
    if (l3->l3info.bufsize < 10 * 1024 * 1024)
      l3->l3info.bufsize = 10 * 1024 * 1024;
  }
}

#if 0
void printL3Info() {
  struct l3info l3Info;
  loadL3cpuidInfo(&l3Info);
  printf("type            : %u\n", l3Info.cpuidInfo.cacheInfo.type);
  printf("level           : %u\n", l3Info.cpuidInfo.cacheInfo.level);
  printf("selfInitializing: %u\n", l3Info.cpuidInfo.cacheInfo.selfInitializing);
  printf("fullyAssociative: %u\n", l3Info.cpuidInfo.cacheInfo.fullyAssociative);
  printf("logIds          : %u\n", l3Info.cpuidInfo.cacheInfo.logIds + 1);
  printf("phyIds          : %u\n", l3Info.cpuidInfo.cacheInfo.phyIds + 1);
  printf("lineSize        : %u\n", l3Info.cpuidInfo.cacheInfo.lineSize + 1);
  printf("partitions      : %u\n", l3Info.cpuidInfo.cacheInfo.partitions + 1);
  printf("associativity   : %u\n", l3Info.cpuidInfo.cacheInfo.associativity + 1);
  printf("sets            : %u\n", l3Info.cpuidInfo.cacheInfo.sets + 1);
  printf("wbinvd          : %u\n", l3Info.cpuidInfo.cacheInfo.wbinvd);
  printf("inclusive       : %u\n", l3Info.cpuidInfo.cacheInfo.inclusive);
  printf("complexIndex    : %u\n", l3Info.cpuidInfo.cacheInfo.complexIndex);
  exit(0);
}
#endif




void *sethead(l3pp_t l3, int set) { //vlist_t list, int count, int offset) {
  vlist_t list = l3->groups[set / l3->groupsize];
  
  int count = l3->l3info.associativity;
  if (count == 0 || vl_len(list) < count)
    count = vl_len(list);

  int offset = (set % l3->groupsize) * L3_CACHELINE;

  for (int i = 0; i < count; i++) {
    LNEXT(OFFSET(vl_get(list, i), offset)) = OFFSET(vl_get(list, (i + 1) % count), offset);
    LNEXT(OFFSET(vl_get(list, i), offset+sizeof(void*))) = OFFSET(vl_get(list, (i + count - 1) % count), offset+sizeof(void *));
  }

  return OFFSET(vl_get(list, 0), offset);
}

void prime(void *pp, int reps) {
  walk((void *)pp, reps);
}

#define str(x) #x
#define xstr(x) str(x)

int probetime(void *pp) {
  if (pp == NULL)
    return 0;
  int rv = 0;
  void *p = (void *)pp;
  uint32_t s = rdtscp();
  do {
    p = LNEXT(p);
  } while (p != (void *) pp);
  return rdtscp()-s;
}

int bprobetime(void *pp) {
  if (pp == NULL)
    return 0;
  return probetime(NEXTPTR(pp));
}


int probecount(void *pp) {
  if (pp == NULL)
    return 0;
  int rv = 0;
  void *p = (void *)pp;
  do {
    uint32_t s = rdtscp();
    p = LNEXT(p);
    s = rdtscp() - s;
    if (s > L3_THRESHOLD)
      rv++;
  } while (p != (void *) pp);
  return rv;
}

int bprobecount(void *pp) {
  if (pp == NULL)
    return 0;
  return probecount(NEXTPTR(pp));
}


static int timedwalk(void *list, register void *candidate) {
#ifdef DEBUG
  static int debug = 100;
  static int debugl = 1000;
#else
#define debug 0
#endif //DEBUG
  if (list == NULL)
    return 0;
  if (LNEXT(list) == NULL)
    return 0;
  void *start = list;
  ts_t ts = ts_alloc();
  void *c2 = (void *)((uintptr_t)candidate ^ 0x200);
  LNEXT(c2) = candidate;
  clflush(c2);
  memaccess(candidate);
  for (int i = 0; i < CHECKTIMES * (debug ? 20 : 1); i++) {
    walk(list, 20);
    void *p = LNEXT(c2);
    uint32_t time = memaccesstime(p);
    ts_add(ts, time);
  }
  int rv = ts_median(ts);
#ifdef DEBUG
  if (!--debugl) {
    debugl=1000;
    debug++;
  }
  if (debug) {
    printf("--------------------\n");
    for (int i = 0; i < TIME_MAX; i++) 
      if (ts_get(ts, i) != 0)
	printf("++ %4d: %4d\n", i, ts_get(ts, i));
    debug--;
  }
#endif //DEBUG
  ts_free(ts);
  return rv;
}

static int checkevict(vlist_t es, void *candidate) {
  if (vl_len(es) == 0)
    return 0;
  for (int i = 0; i < vl_len(es); i++) 
    LNEXT(vl_get(es, i)) = vl_get(es, (i + 1) % vl_len(es));
  int timecur = timedwalk(vl_get(es, 0), candidate);
  return timecur > L3_THRESHOLD;
}


static void *expand(vlist_t es, vlist_t candidates) {
  while (vl_len(candidates) > 0) {
    void *current = vl_poprand(candidates);
    if (checkevict(es, current))
      return current;
    vl_push(es, current);
  }
  return NULL;
}

static void contract(vlist_t es, vlist_t candidates, void *current) {
  for (int i = 0; i < vl_len(es);) {
    void *cand = vl_get(es, i);
    vl_del(es, i);
    clflush(current);
    if (checkevict(es, current))
      vl_push(candidates, cand);
    else {
      vl_insert(es, i, cand);
      i++;
    }
  }
}

static void collect(vlist_t es, vlist_t candidates, vlist_t set) {
  for (int i = vl_len(candidates); i--; ) {
    void *p = vl_del(candidates, i);
    if (checkevict(es, p))
      vl_push(set, p);
    else
      vl_push(candidates, p);
  }
}


static vlist_t map(l3pp_t l3, vlist_t lines) {
#ifdef DEBUG
  printf("%d lines\n", vl_len(lines));
#endif // DEBUG
  vlist_t groups = vl_new();
  vlist_t es = vl_new();
  int nlines = vl_len(lines);
  int fail = 0;
  while (vl_len(lines)) {
    assert(vl_len(es) == 0);
#ifdef DEBUG
    int d_l1 = vl_len(lines);
#endif // DEBUG
    if (fail > 5) 
      break;
    void *c = expand(es, lines);
#ifdef DEBUG
    int d_l2 = vl_len(es);
#endif //DEBUG
    if (c == NULL) {
      while (vl_len(es))
	vl_push(lines, vl_del(es, 0));
#ifdef DEBUG
      printf("set %3d: lines: %4d expanded: %4d c=NULL\n", vl_len(groups), d_l1, d_l2);
#endif // DEBUG
      fail++;
      continue;
    }
    contract(es, lines, c);
    contract(es, lines, c);
    contract(es, lines, c);
#ifdef DEBUG
    int d_l3 = vl_len(es);
#endif //DEBUG
    if (vl_len(es) > l3->l3info.associativity || vl_len(es) < l3->l3info.associativity - 3) {
      while (vl_len(es))
	vl_push(lines, vl_del(es, 0));
#ifdef DEBUG
      printf("set %3d: lines: %4d expanded: %4d contracted: %2d failed\n", vl_len(groups), d_l1, d_l2, d_l3);
#endif // DEBUG
      fail++;
      continue;
    } 
    fail = 0;
    vlist_t set = vl_new();
    vl_push(set, c);
    collect(es, lines, set);
    while (vl_len(es))
      vl_push(set, vl_del(es, 0));
#ifdef DEBUG
    printf("set %3d: lines: %4d expanded: %4d contracted: %2d collected: %d\n", vl_len(groups), d_l1, d_l2, d_l3, vl_len(set));
#endif // DEBUG
    vl_push(groups, set);
    if (l3->l3info.progressNotification) 
      (*l3->l3info.progressNotification)(nlines - vl_len(lines), nlines, l3->l3info.progressNotificationData);
  }

  vl_free(es);
  return groups;
}

static int probemap(l3pp_t l3) {
  if ((l3->l3info.flags & L3FLAG_NOPROBE) != 0)
    return 0;
  vlist_t pages = vl_new();
  for (int i = 0; i < l3->l3info.bufsize; i+= l3->groupsize * L3_CACHELINE) 
    vl_push(pages, l3->buffer + i);
  vlist_t groups = map(l3, pages);

  //Store map results
  l3->ngroups = vl_len(groups);
  l3->groups = (vlist_t *)calloc(l3->ngroups, sizeof(vlist_t));
  for (int i = 0; i < vl_len(groups); i++)
    l3->groups[i] = vl_get(groups, i);
  vl_free(groups);
  vl_free(pages);
  return 1;
}

static int ptemap(l3pp_t l3) {
  if ((l3->l3info.flags & L3FLAG_USEPTE) == 0)
    return 0;
  if (getphysaddr(l3->buffer) == 0)
    return 0;
  if (l3->l3info.slices & (l3->l3info.slices - 1)) // Cannot do non-linear for now
    return 0;
  l3->ngroups = l3->l3info.setsperslice * l3->l3info.slices / l3->groupsize;
  l3->groups = (vlist_t *)calloc(l3->ngroups, sizeof(vlist_t));
  for (int i = 0; i < l3->ngroups; i++)
    l3->groups[i] = vl_new();

  for (int i = 0; i < l3->l3info.bufsize; i+= l3->groupsize * L3_CACHELINE) {
    uintptr_t phys = getphysaddr(l3->buffer + i);
    int slice = addr2slice_linear(phys, l3->l3info.slices);
    int cacheindex = ((phys / L3_CACHELINE) & (l3->l3info.setsperslice - 1));
    vlist_t list = l3->groups[slice * (l3->l3info.setsperslice/l3->groupsize) + cacheindex/l3->groupsize];
    vl_push(list, l3->buffer + i);
  }
  return 1;
}
    



l3pp_t l3_prepare(l3info_t l3info) {
  // Setup
  l3pp_t l3 = (l3pp_t)malloc(sizeof(struct l3pp));
  bzero(l3, sizeof(struct l3pp));
  if (l3info != NULL)
    bcopy(l3info, &l3->l3info, sizeof(struct l3info));
  fillL3Info(l3);

  // Allocate cache  buffer
  int bufsize;
  char *buffer = MAP_FAILED;
#ifdef HUGEPAGES
  if ((l3->l3info.flags & L3FLAG_NOHUGEPAGES) == 0) {
    bufsize = (l3->l3info.bufsize + HUGEPAGESIZE - 1) & ~HUGEPAGEMASK;
    l3->groupsize = L3_GROUPSIZE_FOR_HUGEPAGES;	
    buffer = mmap(NULL, bufsize, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE|HUGEPAGES, -1, 0);
  }
#endif

  if (buffer == MAP_FAILED) {
    bufsize = l3->l3info.bufsize;
    l3->groupsize = L3_SETS_PER_PAGE;
    buffer = mmap(NULL, bufsize, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
  }
  if (buffer == MAP_FAILED) {
    free(l3);
    return NULL;
  }
  l3->buffer = buffer;
  l3->l3info.bufsize = bufsize;

  // Create the cache map
  if (!ptemap(l3)) {
    if (!probemap(l3)) {
      free(l3->buffer);
      free(l3);
      return NULL;
    }
  }

  // Allocate monitored set info
  l3->monitoredbitmap = (uint32_t *)calloc(l3->ngroups*l3->groupsize/32, sizeof(uint32_t));
  l3->monitoredset = (int *)malloc(l3->ngroups * l3->groupsize * sizeof(int));
  l3->monitoredhead = (void **)malloc(l3->ngroups * l3->groupsize * sizeof(void *));
  l3->nmonitored = 0;

  return l3;

}

void l3_release(l3pp_t l3) {
  munmap(l3->buffer, l3->l3info.bufsize);
  free(l3->monitoredbitmap);
  free(l3->monitoredset);
  free(l3->monitoredhead);
  bzero(l3, sizeof(struct l3pp));
  free(l3);
}



int l3_monitor(l3pp_t l3, int line) {
  if (line < 0 || line >= l3->ngroups * l3->groupsize) 
    return 0;
  if (IS_MONITORED(l3->monitoredbitmap, line))
    return 0;
  SET_MONITORED(l3->monitoredbitmap, line);
  l3->monitoredset[l3->nmonitored] = line;
  l3->monitoredhead[l3->nmonitored] = sethead(l3, line);
  l3->nmonitored++;
  return 1;
}

int l3_unmonitor(l3pp_t l3, int line) {
  if (line < 0 || line >= l3->ngroups * l3->groupsize) 
    return 0;
  if (!IS_MONITORED(l3->monitoredbitmap, line))
    return 0;
  UNSET_MONITORED(l3->monitoredbitmap, line);
  for (int i = 0; i < l3->nmonitored; i++)
    if (l3->monitoredset[i] == line) {
      --l3->nmonitored;
      l3->monitoredset[i] = l3->monitoredset[l3->nmonitored];
      l3->monitoredhead[i] = l3->monitoredhead[l3->nmonitored];
      break;
    }
  return 1;
}

void l3_unmonitorall(l3pp_t l3) {
  l3->nmonitored = 0;
  for (int i = 0; i < l3->ngroups * l3->groupsize / 32; i++)
    l3->monitoredset[i] = 0;
}

int l3_getmonitoredset(l3pp_t l3, int *lines, int nlines) {
  if (lines == NULL || nlines == 0)
    return l3->nmonitored;
  if (nlines > l3->nmonitored)
    nlines = l3->nmonitored;
  bcopy(l3->monitoredset, lines, nlines * sizeof(int));
  return l3->nmonitored;
}

void l3_randomise(l3pp_t l3) {
  for (int i = 0; i < l3->nmonitored; i++) {
    int p = random() % (l3->nmonitored - i) + i;
    int t = l3->monitoredset[p];
    l3->monitoredset[p] = l3->monitoredset[i];
    l3->monitoredset[i] = t;
    void *vt = l3->monitoredhead[p];
    l3->monitoredhead[p] = l3->monitoredhead[i];
    l3->monitoredhead[i] = vt;
  }
}

void l3_probe(l3pp_t l3, uint16_t *results) {
  for (int i = 0; i < l3->nmonitored; i++) {
    int t = probetime(l3->monitoredhead[i]);
    results[i] = t > UINT16_MAX ? UINT16_MAX : t;
  }
}

void l3_bprobe(l3pp_t l3, uint16_t *results) {
  for (int i = 0; i < l3->nmonitored; i++) {
    int t = bprobetime(l3->monitoredhead[i]);
    results[i] = t > UINT16_MAX ? UINT16_MAX : t;
  }
}


void l3_probecount(l3pp_t l3, uint16_t *results) {
  for (int i = 0; i < l3->nmonitored; i++)
    results[i] = probecount(l3->monitoredhead[i]);
}

void l3_bprobecount(l3pp_t l3, uint16_t *results) {
  for (int i = 0; i < l3->nmonitored; i++)
    results[i] = bprobecount(l3->monitoredhead[i]);
}


// Returns the number of probed sets in the LLC
int l3_getSets(l3pp_t l3) {
  return l3->ngroups * l3->groupsize;
}

// Returns the number slices
int l3_getSlices(l3pp_t l3) {
  return l3->l3info.slices;
}

// Returns the LLC associativity
int l3_getAssociativity(l3pp_t l3) {
  return l3->l3info.associativity;
}


int l3_repeatedprobe(l3pp_t l3, int nrecords, uint16_t *results, int slot) {
  assert(l3 != NULL);
  assert(results != NULL);

  if (nrecords == 0)
    return 0;

  int len = l3->nmonitored;

  int even = 1;
  int missed = 0;
  uint64_t prev_time = rdtscp64();
  for (int i = 0; i < nrecords; i++, results+=len) {
    if (missed) {
      for (int j = 0; j < len; j++)
	results[j] = 0;
    } else {
      if (even)
	l3_probe(l3, results);
      else
	l3_bprobe(l3, results);
      even = !even;
    }
    if (slot > 0) {
      prev_time += slot;
      missed = slotwait(prev_time);
    }
  }
  return nrecords;
}


int l3_repeatedprobecount(l3pp_t l3, int nrecords, uint16_t *results, int slot) {
  assert(l3 != NULL);
  assert(results != NULL);

  if (nrecords == 0)
    return 0;

  int len = l3->nmonitored;

  int even = 1;
  int missed = 0;
  uint64_t prev_time = rdtscp64();
  for (int i = 0; i < nrecords; i++, results+=len) {
    if (missed) {
      for (int j = 0; j < len; j++)
	results[j] = -1;
    } else {
      if (even)
	l3_probecount(l3, results);
      else
	l3_bprobecount(l3, results);
      even = !even;
    }
    if (slot > 0) {
      prev_time += slot;
      missed = slotwait(prev_time);
    }
  }
  return nrecords;
}

