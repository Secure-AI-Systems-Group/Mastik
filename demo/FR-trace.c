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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fr.h>
#include <pda.h>
#include <util.h>
#include <symbol.h>
#include <time.h>
#include <sys/utsname.h>

#define SAMPLES 100000
#define SLOT	10000
#define IDLE    500
#define THRESHOLD 100

#define MAX_MONITORED 100
#define MAX_EVICTED 100
#define MAX_PDA_TARGETS 10

#define MAX_PDAS 8

void usage(char *p) {
  fprintf(stderr, "Usage: %s [-s <slotlen>] [-c <maxsamplecount>] [-h <threshold>] [-i <idlecount>]\n"
      		  "                [-p <pdacount>] [-H] [-f <file>] \n"
		  "                [-m <monitoraddress>] [-e <evictaddress>] [-t <pdatarget>] ...\n", p);
  exit(1);
}

struct map_entry {
  char *file;
  char *adrsspec;
  uint64_t offset;
  void *map_address;
};

struct config {
  char *progname;
  int samples;
  int slot;
  int threshold;
  int idle;
  int pdacount;
  struct map_entry monitored[MAX_MONITORED];
  int nmonitored;
  struct map_entry evicted[MAX_EVICTED];
  int nevicted;
  struct map_entry pda_targets[MAX_PDA_TARGETS];
  int npdatargets;
  int printheader;
};


void fill_map_entry(struct map_entry *e) {
  if (e->file == NULL) {
    fprintf(stderr, "No filename\n");
    exit(1);
  }
  e->offset = sym_getsymboloffset(e->file, e->adrsspec);
  if (e->offset == ~0ULL) {
    fprintf(stderr, "Cannot find %s in %s\n", e->adrsspec, e->file);
    exit(1);
  }

  e->map_address = map_offset(e->file, e->offset);
  if (e->map_address == NULL) {
    perror(e->file);
    exit(1);
  }
}



static void printmapentries(struct map_entry *entries, int count, char *name) {
  for (int i = 0; i < count; i++) {
    printf("#   %s%d=%s %s 0x%llx\n", name, i, entries[i].file, entries[i].adrsspec, entries[i].offset);
  }
}

static void printuname() {
  struct utsname name;
  uname(&name);
  printf("# sysname=%s\n", name.sysname);
  printf("# nodename=%s\n", name.nodename);
  printf("# release=%s\n", name.release);
  printf("# version=%s\n", name.version);
  printf("# machine=%s\n", name.machine);
}


void readargs(struct config *c, int ac, char **av) {
  char *file = NULL;
  int ch;

  c->samples = SAMPLES;
  c->slot = SLOT;
  c->threshold = THRESHOLD;
  c->idle = IDLE;
  c->pdacount = 0;
  c->npdatargets = 0;
  c->nmonitored = 0;
  c->nevicted = 0;
  c->progname = av[0];
  c->printheader = 0;

  while ((ch = getopt(ac, av, "Hf:s:c:h:i:p:t:m:e:")) != -1) {
    switch (ch) {
      case 'H': 
	c->printheader = 1;
	break;
      case 's':
	c->slot = atoi(optarg);
	break;
      case 'c':
	c->samples = atoi(optarg);
	break;
      case 'h':
	c->threshold = atoi(optarg);
	break;
      case 'i':
	c->idle = atoi(optarg);
	break;
      case 'p':
	c->pdacount = atoi(optarg);
	break;
      case 'f':
	file = optarg;
	break;
      case 't':
	if (c->npdatargets >= MAX_PDA_TARGETS) {
	  fprintf(stderr, "Too many pda targets (Max %d)\n", MAX_PDA_TARGETS);
	  exit(1);
	}
	c->pda_targets[c->npdatargets].file = file;
	c->pda_targets[c->npdatargets].adrsspec = optarg;
       	fill_map_entry(&c->pda_targets[c->npdatargets]);
	c->npdatargets++;
	break;
      case 'm':
	if (c->nmonitored >= MAX_MONITORED) {
	  fprintf(stderr, "Too many monitored locations(Max %d)\n", MAX_MONITORED);
	  exit(1);
	}
	c->monitored[c->nmonitored].file = file;
	c->monitored[c->nmonitored].adrsspec = optarg;
       	fill_map_entry(&c->monitored[c->nmonitored]);
	c->nmonitored++;
	break;
      case 'e':
	if (c->nevicted >= MAX_EVICTED) {
	  fprintf(stderr, "Too many evicted locations(Max %d)\n", MAX_EVICTED);
	  exit(1);
	}
	c->evicted[c->nevicted].file = file;
	c->evicted[c->nevicted].adrsspec = optarg;
       	fill_map_entry(&c->evicted[c->nevicted]);
	c->nevicted++;
	break;
      default: usage(av[0]);
    }
  }

  if (c->nmonitored == 0) 
    usage(av[0]);

  if (c->pdacount > MAX_PDAS) {
    fprintf(stderr, "Too many performance degradation attack threads. (Max %d)\n", MAX_PDAS);
    exit(1);
  }

}

void printheader(struct config *c) {
  time_t now = time(NULL);
  printf("# %s starting at %.24s\n", c->progname, ctime(&now));
  printf("################# CONFIG #################\n");
  printf("# slot=%d\n", c->slot);
  printf("# samples=%d\n", c->samples);
  printf("# threshold=%d\n", c->threshold);
  printf("# idle=%d\n", c->idle);
  printf("# pdathreads=%d\n", c->pdacount);
  printf("# nmonitored=%d\n", c->nmonitored);
  printmapentries(c->monitored, c->nmonitored, "monitor");
  printf("# nevicted=%d\n", c->nevicted);
  printmapentries(c->evicted, c->nevicted, "evict");
  printf("# npdatargets=%d\n", c->npdatargets);
  printmapentries(c->pda_targets, c->npdatargets, "target");
  printf("############## SYSTEM INFO ###############\n");
  printf("# mastik_version=%s\n", mastik_version());
  printuname();
  printf("################## DATA ##################\n");
}

int main(int ac, char **av) {
  struct config c;
  pda_t *pdas = NULL;
  fr_t fr = fr_prepare();

  readargs(&c, ac, av);

  if (c.printheader) 
    printheader(&c);

  for (int i = 0; i < c.nmonitored; i++)
    fr_monitor(fr, c.monitored[i].map_address);

  for (int i = 0; i < c.nevicted; i++)
    fr_evict(fr, c.evicted[i].map_address);



  uint16_t *res = malloc(c.samples * c.nmonitored * sizeof(uint16_t));
  for (int i = 0; i < c.samples * c.nmonitored ; i+= 4096/sizeof(uint16_t))
    res[i] = 1;
  fr_probe(fr, res);

  if (c.pdacount > 0) {
    pdas = calloc(c.pdacount, sizeof(pda_t));
    for (int i = 0; i < c.pdacount; i++) {
      pdas[i] = pda_prepare();
      for (int j = 0; j < c.npdatargets; j++)
	pda_target(pdas[i], c.pda_targets[j].map_address);
      pda_activate(pdas[i]);
    }
  }

  int l = fr_trace(fr, c.samples, res, c.slot, c.threshold, c.idle);

  if (c.pdacount > 0) {
    for (int i = 0; i < c.pdacount; i++)
      pda_release(pdas[i]);
  }

  for (int i = 0; i < l; i++) {
    for (int j = 0; j < c.nmonitored; j++)
      printf("%d ", res[i * c.nmonitored + j]);
    putchar('\n');
  }

  free(res);
  fr_release(fr);
}
