/* mmopenshift.c
 * Annotate message with OpenShift-specific properties. Requires
 * imuxsock with Annotate=on, ParseTrusted=on, UsePIDFromSystem=on.
 *
 * Copyright 2014 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include "rsyslog.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <pthread.h>
#include "conf.h"
#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"
#include "hashtable.h"
#include "hashtable_itr.h"

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("mmopenshift")


DEFobjCurrIf(errmsg);
DEF_OMOD_STATIC_DATA

/* module global variables */
static es_str_t* uidProperty;


// struct to hold OpenShift metadata
typedef struct _gearInfo {
  // OpenShift application UUID
  char* appUuid;

  // OpenShift gear UUID
  char* gearUuid;

  // OpenShift application domain
  char* namespace;

  // pointers to prev/next oldest gearInfo
  // used during FIFO eviction if the cache gets full
  struct _gearInfo* prev;
  struct _gearInfo* next;
} gearInfo;

// struct to hold plugin instance data
typedef struct _instanceData {
  // sentinel node
  gearInfo* sentinel;

  // map from uid to gearInfo
  struct hashtable *uidMap;

  // map from uuid to uid (needed for deletion)
  struct hashtable *uuidMap;

  // thread for using inotify to watch for gear directory deletions
  pthread_t watchThread;

  // mutex to use for thread safety when modifying the 2 maps
  pthread_mutex_t lock;

  // file descriptors for a pipe so we can signal the inotify thread to stop
  int pipeFds[2];

  // inotify file descriptor
  int inotifyFd;

  // inotify watch descriptor
  int inotifyWatchFd;

  // buffer for getpwuid
  char* getpwuidBuffer;

  // buffer size
  size_t getpwuidBufferSize;
} instanceData;

/* module-global parameters */
static struct cnfparamdescr modpdescr[] = {
  { "gearuidstart", eCmdHdlrPositiveInt, 0 },
  { "gearbasedir", eCmdHdlrGetWord, 0 },
  { "maxcachesize", eCmdHdlrPositiveInt, 0 },
};

static struct cnfparamblk modpblk =
  { CNFPARAMBLK_VERSION,
    sizeof(modpdescr)/sizeof(struct cnfparamdescr),
    modpdescr
  };

struct modConfData_s {
  rsconf_t *pConf;  /* our overall config object */

  // minimum uid value for OpenShift gears
  uid_t gearUidStart;

  // base directory where OpenShift gears are stored
  char* gearBaseDir;

  // maximum number of items to keep in the gear info cache
  unsigned int maxCacheSize;
};

static modConfData_t *runModConf = NULL;/* modConf ptr to use for the current exec process */

/**
 * Hash function for the uid->gearInfo map
 *
 * Key type is uid_t
 *
 * Simplistic implementation just uses the value of the uid as the hash value
 */
static unsigned int
uidHash(void *k)
{
  return((unsigned) *((uid_t*) k));
}

/**
 * Key equality function for the uid->gearInfo map
 *
 * 2 keys are equal if the values they point to (of type uid_t) are identical
 */
static int
uidKeyEquals(void *key1, void *key2)
{
  return *((uid_t*) key1) == *((uid_t*) key2);
}

/**
 * Value "destructor" function for the uid->gearInfo map
 *
 * Invoked when a key is removed from the uidMap.
 *
 * Value type is gearInfo.
 *
 * Frees the memory we previously allocated in the gearInfo struct as well as
 * the struct itself.
 */
static void
uidValueDestroy(void* value) {
  gearInfo* gi = (gearInfo*)value;
  free(gi->appUuid);
  free(gi->gearUuid);
  free(gi->namespace);
  free(gi);
}

/**
 * Hash function for the uuid->uid map
 *
 * Key type is char* (gear UUID)
 *
 * Implements the djb2 hash function
 *
 * See http://www.cse.yorku.ca/~oz/hash.html for more details
 */
static unsigned int
uuidHash(void* k)
{
  char* str = (char*)k;

  unsigned int hashValue = 5381;
  int c;

  while ((c = *str++)) {
    hashValue = ((hashValue << 5) + hashValue) + c; // hashValue * 33 + c
  }

  return hashValue;
}

/**
 * Key equality function for the uuid->uid map
 *
 * 2 keys are equal if strcmp returns 0 (string equality)
 */
static int
uuidKeyEquals(void *key1, void *key2)
{
  return !strcmp((char*)key1, (char*)key2);
}

/**
 * Value "destructor" function for the uuid->uid map
 *
 * Simply frees the value
 */
static void
uuidValueDestroy(void* value) {
  free(value);
}


BEGINdbgPrintInstInfo
  struct hashtable_itr* iter;
  gearInfo* gi;
CODESTARTdbgPrintInstInfo
  DBGPRINTF("mmopenshift\n");
  DBGPRINTF("\tgearUidStart=%d\n", runModConf->gearUidStart);
  DBGPRINTF("\tgearBaseDir=%s\n", runModConf->gearBaseDir);
  DBGPRINTF("\tmaxCacheSize=%d\n", runModConf->maxCacheSize);
  DBGPRINTF("\tgearInfo linked list:\n");
  gi = pData->sentinel->next;
  while(gi != pData->sentinel) {
    DBGPRINTF("\t\tapp=%s gear=%s ns=%s\n", gi->appUuid, gi->gearUuid, gi->namespace);
    gi = gi->next;
  }
  if(pData->uidMap != NULL && hashtable_count(pData->uidMap) > 0) {
    DBGPRINTF("\tuidMap:\n");
    iter = hashtable_iterator(pData->uidMap);
    do {
      gi = (gearInfo*)hashtable_iterator_value(iter);
      DBGPRINTF("\t\tuid=%d app=%s gear=%s ns=%s\n", *(uid_t*)hashtable_iterator_key(iter), gi->appUuid, gi->gearUuid, gi->namespace);
    } while(hashtable_iterator_advance(iter));
  }
  if(pData->uuidMap != NULL && hashtable_count(pData->uuidMap) > 0) {
    DBGPRINTF("\tuuidMap:\n");
    iter = hashtable_iterator(pData->uuidMap);
    do {
      DBGPRINTF("\t\tuuid=%s uid=%d\n", (char*)hashtable_iterator_key(iter), *(uid_t*)hashtable_iterator_value(iter));
    } while(hashtable_iterator_advance(iter));
  }
ENDdbgPrintInstInfo


BEGINcreateInstance
CODESTARTcreateInstance
ENDcreateInstance


BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
ENDisCompatibleWithFeature


BEGINfreeInstance
CODESTARTfreeInstance
  // shut down inotify thread by writing 1 character to the write end of the pipe fd pair
  int rc = -1;
  rc = write(pData->pipeFds[1], "x", 1);

  // lock the mutex for the 2 maps
  pthread_mutex_lock(&pData->lock);

  // free uidMap hashtable
  if(pData->uidMap != NULL) {
    hashtable_destroy(pData->uidMap, 1);
  }

  // free uuidMap hashtable
  if(pData->uuidMap != NULL) {
    hashtable_destroy(pData->uuidMap, 1);
  }

  // unlock the mutex
  pthread_mutex_unlock(&pData->lock);

  // destroy it
  pthread_mutex_destroy(&pData->lock);

  if(pData->inotifyFd != -1) {
    // close the inotify fd
    close(pData->inotifyFd);
  }

  if(pData->pipeFds[0] != -1) {
    // close the read end of the pipe fd pair
    close(pData->pipeFds[0]);
  }

  if(pData->pipeFds[1] != -1) {
    // close the write end of the pipe fd pair
    close(pData->pipeFds[1]);
  }

  free(pData->getpwuidBuffer);
ENDfreeInstance


/**
 * Set defaults for the module params
 */
static inline void
setModuleParamDefaults() {
  // OpenShift usually starts gears at uid 1000
  runModConf->gearUidStart = 1000;

  // keep up to 100 gears in the cache
  runModConf->maxCacheSize = 100;

  // use strdup here so we can free this var later
  // regardless of if it was the default or user specified
  runModConf->gearBaseDir = strdup("/var/lib/openshift");
}

/**
 * Set defaults for the plugin instance
 */
static inline void
setInstParamDefaults(instanceData *pData)
{
}

/**
 * This method runs in a separate thread and is used to remove entries from
 * the uidMap and uuidMap caches when a gear is deleted from a node.
 *
 * Monitor the gear base directory for directory deletions via inotify, and attempt to
 * evict the appropriate entry from the caches using the directory name
 * as the key into the uuidMap, since the directory name should be the gear UUID.
 */
static void watchThread(instanceData* pData) {
  DBGPRINTF("mmopenshift: starting watchThread\n");
  // size the buffer to hold 1 struct + a filename of 50 chars + \0
  size_t bufferSize = sizeof(struct inotify_event) + NAME_MAX + 1;

  // the buffer we'll use to hold the inotify struct
  char buffer[bufferSize];

  // the event pointer we'll be working with
  struct inotify_event *event;

  // file descriptors we'll be reading from
  fd_set readFds;

  int rc = 0;
  int done = 0;

  // loop until we're notified to stop via the pipe fd
  while(!done) {
    // clear out the file descriptor set
    FD_ZERO(&readFds);

    // add the inotify file descriptor
    FD_SET(pData->inotifyFd, &readFds);

    // add the pipe file descriptor (so we can receive notification to stop)
    FD_SET(pData->pipeFds[0], &readFds);

    // check for any available data
    // don't set a timeout as we'll be using the pipe to exit
    int maxFd = (pData->inotifyFd > pData->pipeFds[0]) ? pData->inotifyFd : pData->pipeFds[0];
    rc = select(maxFd + 1, &readFds, NULL, NULL, NULL);
    if (rc == -1) {
      if(errno == EINTR) {
        // got interrupted; retry the select
        continue;
      } else {
        errmsg.LogError(errno, RS_RET_ERR, "mmopenshift: select() error in watch thread.");
        done = 1;
        break;
      }
    } else {
      if(FD_ISSET(pData->pipeFds[0], &readFds)) {
        // the pipe had data on it, which means we're ready to shut down
        rc = read(pData->pipeFds[0], buffer, 1);
        done = 1;
      } else if(FD_ISSET(pData->inotifyFd, &readFds)) {
        // we have inotify data
        while((rc = read(pData->inotifyFd, buffer, bufferSize)) == -1) {
          if(errno == EINTR) {
            continue;
          } else {
            errmsg.LogError(errno, RS_RET_ERR, "mmopenshift: read() error in watch thread.");
            done = 1;
            break;
          }
        }
        DBGPRINTF("mmopenshift: read finished with rc=%d\n", rc);
        if(rc) {
          DBGPRINTF("mmopenshift: read %d bytes from inotifyFd\n", rc);
          int bufferIndex = 0;
          do {
            DBGPRINTF("mmopenshift: bufferIndex = %d\n", bufferIndex);
            // read succeeded, cast the buffer to the event variable
            event = (struct inotify_event*)&buffer[bufferIndex];
            DBGPRINTF("mmopenshift: event->len = %d\n", event->len);
            if(event->len) {
              // we have a length for the filename
              if(event->mask & IN_DELETE) {
                DBGPRINTF("mmopenshift: delete event\n");
                // it was a delete event
                if(event->mask & IN_ISDIR) {
                  DBGPRINTF("mmopenshift: delete directory\n");
                  // a directory was deleted, so we need to remove the data
                  // from the hashtables, if it's there

                  // acquire the lock
                  pthread_mutex_lock(&pData->lock);

                  // event->name should be a gear uuid; see if it's in the
                  // uuid -> uid map
                  DBGPRINTF("mmopenshift: trying to remove %s from uuidMap\n", event->name);
                  uid_t* uid = hashtable_remove(pData->uuidMap, event->name);
                  if(uid != NULL) {
                    DBGPRINTF("mmopenshift: removed uid = %d\n", *uid);
                    DBGPRINTF("mmopenshift: trying to remove from uidMap\n");
                    gearInfo* gi = hashtable_remove(pData->uidMap, uid);
                    if(NULL == gi) {
                      DBGPRINTF("mmopenshift: tried to remove uid %d from uidMap, but it wasn't there\n", *uid);
                    } else {
                      // update linked list pointers
                      gi->prev->next = gi->next;
                      gi->next->prev = gi->prev;

                      DBGPRINTF("mmopenshift: freeing gearInfo\n");
                      free(gi);
                      DBGPRINTF("mmopenshift: removal from uidMap succeeded\n");
                    }

                    DBGPRINTF("mmopenshift: freeing uid\n");
                    free(uid);
                  } else {
                    DBGPRINTF("mmopenshift: removed uid was NULL\n");
                  }

                  dbgPrintInstInfo(pData);

                  pthread_mutex_unlock(&pData->lock);
                }
              }
            }
            bufferIndex += sizeof(struct inotify_event) + event->len;
            DBGPRINTF("mmopenshift: end of loop, bufferIndex now = %d\n", bufferIndex);
          } while (bufferIndex < rc);
        }
      }
    }
  }
  DBGPRINTF("mmopenshift: ending watchThread\n");
}

BEGINbeginCnfLoad
CODESTARTbeginCnfLoad
  runModConf = pModConf;
  pModConf->pConf = pConf;
ENDbeginCnfLoad

BEGINendCnfLoad
CODESTARTendCnfLoad
ENDendCnfLoad

BEGINsetModCnf
  struct cnfparamvals *pvals;
  int i;
CODESTARTsetModCnf
  setModuleParamDefaults();

  pvals = nvlstGetParams(lst, &modpblk, NULL);
  if(pvals == NULL) {
    errmsg.LogError(0, RS_RET_MISSING_CNFPARAMS, "error processing module "
        "config parameters [module(...)]");
    ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
  }

  // check for config params specified in the config file
  for(i = 0 ; i < modpblk.nParams ; ++i) {
    if(!pvals[i].bUsed) {
      continue;
    }
    if(!strcmp(modpblk.descr[i].name, "gearuidstart")) {
      runModConf->gearUidStart = (uid_t)pvals[i].val.d.n;
    } else if(!strcmp(modpblk.descr[i].name, "gearbasedir")) {
      runModConf->gearBaseDir = es_str2cstr(pvals[i].val.d.estr, NULL);
    } else if(!strcmp(modpblk.descr[i].name, "maxcachesize")) {
      runModConf->maxCacheSize = (int)pvals[i].val.d.n;
    } else {
      dbgprintf("mmopenshift: program error, non-handled "
        "param '%s'\n", modpblk.descr[i].name);
    }
  }

finalize_it:
  if(pvals != NULL) {
    cnfparamvalsDestruct(pvals, &modpblk);
  }
ENDsetModCnf

BEGINcheckCnf
CODESTARTcheckCnf
ENDcheckCnf

BEGINactivateCnf
CODESTARTactivateCnf
  runModConf = pModConf;
ENDactivateCnf

BEGINfreeCnf
CODESTARTfreeCnf
  // need to free gearBaseDir as it either has the default value which we
  // got via strdup(), or it came from the config system, and it's up to us
  // to free in that case too
  free(runModConf->gearBaseDir);
ENDfreeCnf

BEGINnewActInst
  int rc;
CODESTARTnewActInst
  (void) lst; /* prevent compiler warning */
  DBGPRINTF("newActInst (mmopenshift)\n");

  // follow conventions from other plugins
  CODE_STD_STRING_REQUESTnewActInst(1)
  CHKiRet(OMSRsetEntry(*ppOMSR, 0, NULL, OMSR_TPL_AS_MSG));
  CHKiRet(createInstance(&pData));

  // create the uid->gearInfo map
  pData->uidMap = create_hashtable(runModConf->maxCacheSize, uidHash, uidKeyEquals, uidValueDestroy);
  if(NULL == pData->uidMap) {
    errmsg.LogError(0, RS_RET_ERR, "error: could not create uidMap, cannot activate action");
    ABORT_FINALIZE(RS_RET_ERR);
  }

  // create the uuid->uid map
  pData->uuidMap = create_hashtable(runModConf->maxCacheSize, uuidHash, uuidKeyEquals, uuidValueDestroy);
  if(NULL == pData->uidMap) {
    errmsg.LogError(0, RS_RET_ERR, "error: could not create uuidMap, cannot activate action");
    ABORT_FINALIZE(RS_RET_ERR);
  }

  CHKmalloc(pData->sentinel = MALLOC(sizeof(gearInfo)));
  pData->sentinel->prev = pData->sentinel;
  pData->sentinel->next = pData->sentinel;

  // create the pipe which we'll use to signal the inotify thread to stop
  pipe(pData->pipeFds);

  // set up inotify
  pData->inotifyFd = inotify_init();
  if(-1 == pData->inotifyFd) {
    errmsg.LogError(0, RS_RET_ERR, "error: could not initialize inotify");
    ABORT_FINALIZE(RS_RET_ERR);
  }

  // watch for deletions in the gear base dir
  pData->inotifyWatchFd = inotify_add_watch(pData->inotifyFd, runModConf->gearBaseDir, IN_DELETE);
  if(-1 == pData->inotifyWatchFd) {
    errmsg.LogError(0, RS_RET_ERR, "error: could not add inotify watch");
    ABORT_FINALIZE(RS_RET_ERR);
  }

  // set up our mutex
  rc = pthread_mutex_init(&pData->lock, NULL);
  if(rc != 0) {
    errmsg.LogError(0, RS_RET_ERR, "error: could not create mutex, rc=%d", rc);
    ABORT_FINALIZE(RS_RET_ERR);
  }

  // create the inotify watch thread
  DBGPRINTF("mmopenshift: creating watchThread\n");
  rc = pthread_create(&pData->watchThread, NULL, (void*)&watchThread, pData);
  if(rc != 0) {
    errmsg.LogError(0, RS_RET_ERR, "error: could not create thread, rc=%d", rc);
    ABORT_FINALIZE(RS_RET_ERR);
  }

  pData->getpwuidBufferSize = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (pData->getpwuidBufferSize == (size_t)-1) {
    pData->getpwuidBufferSize = 16384; // should be plenty big
  }

  CHKmalloc(pData->getpwuidBuffer = MALLOC(pData->getpwuidBufferSize));

CODE_STD_FINALIZERnewActInst
ENDnewActInst


BEGINtryResume
CODESTARTtryResume
ENDtryResume


/**
 * Helper method to read an OpenShift environment variable file
 *
 * Reads $gearBaseDir/$gearUuid/.env/$varName and returns it as a char*
 *
 * The returned char* is malloc'd here and it is the responsibility of the
 * caller to free it later.
 */
static char* readOpenShiftEnvVar(char* gearBaseDir, char* gearUuid, char* varName) {
  rsRetVal iRet = RS_RET_OK;
  char* data = NULL;

  // using snprintf this way, it will return the # of bytes needed to store
  // the entire formatting string (excluding the null terminator)
  size_t needed = snprintf(NULL, 0, "%s/%s/.env/%s", gearBaseDir, gearUuid, varName) + 1;

  char* filename;
  CHKmalloc(filename = MALLOC(needed));
  snprintf(filename, needed, "%s/%s/.env/%s", gearBaseDir, gearUuid, varName);

  FILE* fp = fopen(filename, "r");

  off_t size = 0;
  CHKiRet(getFileSize((uchar*)filename, &size));

  // no longer needed, so free it
  free(filename);

  // add space for \0
  size++;

  CHKmalloc(data = MALLOC(size));

  if(fgets(data, size, fp) == NULL) {
    // there was an error reading the file
    free(data);
    data = NULL;
  }

  fclose(fp);

finalize_it:
  return data;
}


/**
 * This is the main message processing method
 */
BEGINdoAction
  // the actual message object
  msg_t* pMsg;
  struct json_object* pJson;
  struct json_object* jval;
  rsRetVal localRet;
  uid_t uid;
  gearInfo* gear = NULL;
  gearInfo* gearToDelete = NULL;
  char* appUuid = NULL;
  char* gearUuid = NULL;
  char* namespace = NULL;
  struct passwd pwdata;
  struct passwd* pwdataResult;
CODESTARTdoAction
  pMsg = (msg_t*) ppString[0];

  DBGPRINTF("mmopenshift: looking for !uid\n");
  localRet = jsonFind(pMsg, uidProperty, &pJson);

  if(pJson != NULL) {
    DBGPRINTF("mmopenshift: found !uid\n");

    DBGPRINTF("mmopenshift: retrieving uid value\n");
    uid = json_object_get_int(pJson);
    DBGPRINTF("mmopenshift: uid=%d\n", uid);

    if(uid < runModConf->gearUidStart) {
      DBGPRINTF("mmopenshift: not an openshift uid\n");
      goto finalize_it;
    }

    DBGPRINTF("mmopenshift: acquiring lock\n");
    pthread_mutex_lock(&pData->lock);

    DBGPRINTF("mmopenshift: searching uidMap for uid %d\n", uid);
    gear = hashtable_search(pData->uidMap, &uid);

    if(NULL == gear) {
      DBGPRINTF("mmopenshift: key not found\n");

      DBGPRINTF("mmopenshift: alloc for gearInfo\n");
      CHKmalloc(gear = MALLOC(sizeof(gearInfo)));

      DBGPRINTF("mmopenshift: getpwuid\n");
      int rc = getpwuid_r(uid, &pwdata, pData->getpwuidBuffer, pData->getpwuidBufferSize, &pwdataResult);
      if (pwdataResult == NULL) {
        if (rc == 0) {
          DBGPRINTF("mmopenshift: unable to find uid %d\n", uid);
          pthread_mutex_unlock(&pData->lock);
          // don't do any additional processing
          FINALIZE
        } else {
          errmsg.LogError(rc, RS_RET_ERR, "mmopenshift: error looking up user information for uid %d", uid);
          pthread_mutex_unlock(&pData->lock);
          // don't do any additional processing
          FINALIZE
        }
      }

      gearUuid = pwdata.pw_name;

      //NOTE: readOpenShiftEnvVar returns memory that was malloc'd
      //NOTE: return value will be NULL if not found
      appUuid = readOpenShiftEnvVar(runModConf->gearBaseDir, gearUuid, "OPENSHIFT_APP_UUID");
      namespace = readOpenShiftEnvVar(runModConf->gearBaseDir, gearUuid, "OPENSHIFT_NAMESPACE");

      // fill in the gearInfo data
      // gearUuid
      CHKmalloc(gear->gearUuid = MALLOC(strlen(gearUuid) + 1));
      strcpy(gear->gearUuid, gearUuid);

      // appUuid
      // NOTE: this was malloc'd above by readOpenShiftEnvVar and we'll free it
      // in the hash's custom destructor function
      gear->appUuid = appUuid;

      // namespace
      // NOTE: this was malloc'd above by readOpenShiftEnvVar and we'll free it
      // in the hash's custom destructor function
      gear->namespace = namespace;

      // allocate memory for the key (uid)
      uid_t* keybuf;
      CHKmalloc(keybuf = MALLOC(sizeof(uid_t)));
      *keybuf = uid;

      // new gear's "next" is the sentinel aka end of list
      gear->next = pData->sentinel;

      // new gear's "prev" is the current last node
      gear->prev = pData->sentinel->prev;

      // set sentinel->prev to new gear
      gear->next->prev = gear;

      // update last node's next to point at this new node
      gear->prev->next = gear;

      DBGPRINTF("Added new gearInfo\n");
      dbgPrintInstInfo(pData);

      // see if we're at capacity and need to delete the oldest entry
      if(hashtable_count(pData->uidMap) >= runModConf->maxCacheSize) {
        DBGPRINTF("mmopenshift: cache is full - need to delete oldest entry\n");
        gearToDelete = pData->sentinel->next;
      }

      // delete the oldest entry if necessary
      if(gearToDelete != NULL) {
        gearToDelete->prev->next = gearToDelete->next;
        gearToDelete->next->prev = gearToDelete->prev;

        DBGPRINTF("mmopenshift: removing %s from uuid map\n", gearToDelete->gearUuid);
        uid_t* uidToDelete = hashtable_remove(pData->uuidMap, gearToDelete->gearUuid);
        if(uidToDelete != NULL) {
          DBGPRINTF("mmopenshift: removing %d from uid map\n", *uidToDelete);
          void* deleted = hashtable_remove(pData->uidMap, uidToDelete);
          if (deleted != NULL) {
            DBGPRINTF("mmopenshift: found key in map\n");
          } else {
            DBGPRINTF("mmopenshift: unable to find %d in uid map\n", *uidToDelete);
          }

          free(uidToDelete);
          free(gearToDelete);
        }

        dbgPrintInstInfo(pData);
      }

      DBGPRINTF("mmopenshift: adding to hash\n");
      hashtable_insert(pData->uidMap, keybuf, gear);

      // allocate memory for the value (uid)
      CHKmalloc(keybuf = MALLOC(sizeof(uid_t)));
      *keybuf = uid;
      hashtable_insert(pData->uuidMap, strdup(gearUuid), keybuf);

      dbgPrintInstInfo(pData);
    } else {
      DBGPRINTF("mmopenshift: found key in hash\n");

      appUuid = gear->appUuid;
      gearUuid = gear->gearUuid;
      namespace = gear->namespace;
    }

    pJson = json_object_new_object();

    if(appUuid != NULL) {
      jval = json_object_new_string(appUuid);
      json_object_object_add(pJson, "AppUuid", jval);
    }

    if(gearUuid != NULL) {
      jval = json_object_new_string(gearUuid);
      json_object_object_add(pJson, "GearUuid", jval);
    }

    if(namespace != NULL) {
      jval = json_object_new_string(namespace);
      json_object_object_add(pJson, "Namespace", jval);
    }

    json_object_object_add(pMsg->json, "OpenShift", pJson);

    //UNLOCK
    pthread_mutex_unlock(&pData->lock);
  }
finalize_it:
ENDdoAction


BEGINparseSelectorAct
CODESTARTparseSelectorAct
CODE_STD_STRING_REQUESTparseSelectorAct(1)
  if(strncmp((char*) p, ":mmopenshift:", sizeof(":mmopenshift:") - 1)) {
    errmsg.LogError(0, RS_RET_LEGA_ACT_NOT_SUPPORTED,
      "mmopenshift supports only v6+ config format, use: "
      "action(type=\"mmopenshift\" ...)");
  }
  ABORT_FINALIZE(RS_RET_CONFLINE_UNPROCESSED);
CODE_STD_FINALIZERparseSelectorAct
ENDparseSelectorAct


BEGINmodExit
CODESTARTmodExit
  objRelease(errmsg, CORE_COMPONENT);
ENDmodExit


BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_OMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_QUERIES
CODEqueryEtryPt_STD_CONF2_setModCnf_QUERIES
ENDqueryEtryPt


BEGINmodInit()
CODESTARTmodInit
  *ipIFVersProvided = CURR_MOD_IF_VERSION; /* we only support the current interface specification */
CODEmodInit_QueryRegCFSLineHdlr
  DBGPRINTF("mmopenshift: module compiled with rsyslog version %s.\n", VERSION);
  CHKiRet(objUse(errmsg, CORE_COMPONENT));

  // initialize estring for !uid json path
  uidProperty = es_newStrFromCStr("!uid", 4);
ENDmodInit
