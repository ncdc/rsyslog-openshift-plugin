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

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("mmopenshift")


DEFobjCurrIf(errmsg);
DEF_OMOD_STATIC_DATA

/* module global variables */
static es_str_t* es_uid = NULL;

typedef struct _instanceData {
  uid_t gearUidStart;
  struct hashtable *uidMap;
  struct hashtable *uuidMap;
  pthread_t watchThread;
  int watchThreadRunning;
  pthread_mutex_t lock;
  int pipeFds[2];
  int inotifyFd;
  int inotifyWatchFd;
} instanceData;

// uid -> gearInfo
typedef struct _gearInfo {
  char* appUuid;
  char* gearUuid;
  char* namespace;
} gearInfo;

static unsigned int
uidHash(void *k)
{
	return((unsigned) *((uid_t*) k));
}

static int
uidKeyEquals(void *key1, void *key2)
{
	return *((uid_t*) key1) == *((uid_t*) key2);
}

static void
uidValueDestroy(void* value) {
  gearInfo* gi = (gearInfo*)value;
  free(gi->appUuid);
  free(gi->gearUuid);
  free(gi->namespace);
  free(gi);
}

// uuid -> uid
static unsigned int
uuidHash(void* k)
{
  char* str = (char*)k;

  //djb2
  unsigned int hash = 5381;
  int c;

  while (c = *str++) {
    hash = ((hash << 5) + hash) + c; // hash * 33 + c
  }

  return hash;
}

static int
uuidKeyEquals(void *key1, void *key2)
{
	return !strcmp((char*)key1, (char*)key2);
}

static void
uuidValueDestroy(void* value) {
  free(value);
}



struct modConfData_s {
	rsconf_t *pConf;	/* our overall config object */
};
static modConfData_t *loadModConf = NULL;/* modConf ptr to use for the current load process */
static modConfData_t *runModConf = NULL;/* modConf ptr to use for the current exec process */


/* tables for interfacing with the v6 config system */
/* action (instance) parameters */
static struct cnfparamdescr actpdescr[] = {
	{ "gearuidstart", eCmdHdlrPositiveInt, 0 },
};
static struct cnfparamblk actpblk =
	{ CNFPARAMBLK_VERSION,
	  sizeof(actpdescr)/sizeof(struct cnfparamdescr),
	  actpdescr
	};

BEGINbeginCnfLoad
CODESTARTbeginCnfLoad
	loadModConf = pModConf;
	pModConf->pConf = pConf;
ENDbeginCnfLoad

BEGINendCnfLoad
CODESTARTendCnfLoad
ENDendCnfLoad

BEGINcheckCnf
CODESTARTcheckCnf
ENDcheckCnf

BEGINactivateCnf
CODESTARTactivateCnf
	runModConf = pModConf;
ENDactivateCnf

BEGINfreeCnf
CODESTARTfreeCnf
ENDfreeCnf


BEGINcreateInstance
CODESTARTcreateInstance
ENDcreateInstance


BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
ENDisCompatibleWithFeature


BEGINfreeInstance
CODESTARTfreeInstance
  // shut down inotify thread
  int rc = -1;
  rc = write(pData->pipeFds[1], "x", 1);

  pthread_mutex_lock(&pData->lock);

  //TODO check rc
  // free uidMap hashtable
  if(pData->uidMap != NULL) {
    hashtable_destroy(pData->uidMap, 1);
  }

  // free uuidMap hashtable
  if(pData->uuidMap != NULL) {
    hashtable_destroy(pData->uuidMap, 1);
  }

  pthread_mutex_unlock(&pData->lock);

  rc = pthread_mutex_destroy(&pData->lock);
  //TODO check rc
ENDfreeInstance


static inline void
setInstParamDefaults(instanceData *pData)
{
	pData->gearUidStart = 1000;
	pData->watchThreadRunning = 1;
}

static void watchThread(instanceData* pData) {
  // size the buffer to hold 1 struct + a filename of 50 chars + \0
  size_t bufferSize = sizeof(struct inotify_event) + 51;
  // the buffer we'll use to hold the inotify struct
  char buffer[bufferSize];
  // the event pointer we'll be working with
  struct inotify_event *event;
  // file descriptors we'll be reading from
  fd_set readFds;
  int rc = 0;
  int done = 0;
  int count = 0;
  while(!done) {
    // clear out the file descriptor set
    FD_ZERO(&readFds);
    // add the inotify file descriptor
    FD_SET(pData->inotifyFd, &readFds);
    // add the pipe file descriptor (so we can receive notification to stop)
    FD_SET(pData->pipeFds[0], &readFds);

    // check for any available data
    // don't set a timeout as we'll be using the pipe to exit
    rc = select(FD_SETSIZE, &readFds, NULL, NULL, NULL);
    if (rc == -1) {
      // TODO error
    } else {
      if(FD_ISSET(pData->pipeFds[0], &readFds)) {
        // the pipe had data on it, which means we're ready to shut down
        count = read(pData->pipeFds[0], buffer, 1);
        done = 1;
      } else if(FD_ISSET(pData->inotifyFd, &readFds)) {
        // we have inotify data
        count = read(pData->inotifyFd, buffer, bufferSize);
        if(count) {
          // read succeeded, cast the buffer to the event variable
          event = (struct inotify_event*)&buffer;
          if(event->len) {
            // we have a length for the filename
            if(event->mask & IN_DELETE) {
              // it was a delete event
              if(event->mask & IN_ISDIR) {
                // a directory was deleted, so we need to remove the data
                // from the hashtables, if it's there

                // acquire the lock
                pthread_mutex_lock(&pData->lock);

                // event->name should be a gear uuid; see if it's in the
                // uuid -> uid map
                uid_t* uid = hashtable_remove(pData->uuidMap, event->name);
                if(uid != NULL) {
                  gearInfo* gi = hashtable_remove(pData->uidMap, uid);
                  if(NULL == gi) {
                    //TODO warn that we couldn't find the gearInfo in uidMap
                  }
                }

                pthread_mutex_unlock(&pData->lock);
              }
            }
          }
        } else {
          // TODO error
        }
      }
    }
  }

  pData->watchThreadRunning = 0;
}

BEGINnewActInst
	struct cnfparamvals *pvals;
	int i;
	int rc;
CODESTARTnewActInst
	DBGPRINTF("newActInst (mmopenshift)\n");
	if((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
	}

	CODE_STD_STRING_REQUESTnewActInst(1)
	CHKiRet(OMSRsetEntry(*ppOMSR, 0, NULL, OMSR_TPL_AS_MSG));
	CHKiRet(createInstance(&pData));
	setInstParamDefaults(pData);

	for(i = 0 ; i < actpblk.nParams ; ++i) {
		if(!pvals[i].bUsed) {
			continue;
    }
		if(!strcmp(actpblk.descr[i].name, "gearuidstart")) {
		  pData->gearUidStart = (uid_t)pvals[i].val.d.n;
		} else {
			dbgprintf("mmopenshift: program error, non-handled "
			  "param '%s'\n", actpblk.descr[i].name);
		}
	}

	pData->uidMap = create_hashtable(100, uidHash, uidKeyEquals, uidValueDestroy);
	if(NULL == pData->uidMap) {
		errmsg.LogError(0, RS_RET_ERR, "error: could not create uidMap, cannot activate action");
		ABORT_FINALIZE(RS_RET_ERR);
  }

	pData->uuidMap = create_hashtable(100, uuidHash, uuidKeyEquals, uuidValueDestroy);
	if(NULL == pData->uidMap) {
		errmsg.LogError(0, RS_RET_ERR, "error: could not create uuidMap, cannot activate action");
		ABORT_FINALIZE(RS_RET_ERR);
  }

  pipe(pData->pipeFds);

  pData->inotifyFd = inotify_init();
  if(-1 == pData->inotifyFd) {
		errmsg.LogError(0, RS_RET_ERR, "error: could not initialize inotify");
		ABORT_FINALIZE(RS_RET_ERR);
  }

  pData->inotifyWatchFd = inotify_add_watch(pData->inotifyFd, "/var/lib/openshift", IN_DELETE);
  if(-1 == pData->inotifyWatchFd) {
		errmsg.LogError(0, RS_RET_ERR, "error: could not add inotify watch");
		ABORT_FINALIZE(RS_RET_ERR);
  }

  rc = pthread_mutex_init(&pData->lock, NULL);
  if(rc != 0) {
		errmsg.LogError(0, RS_RET_ERR, "error: could not create mutex, rc=%d", rc);
		ABORT_FINALIZE(RS_RET_ERR);
  }

  rc = pthread_create(&pData->watchThread, NULL, (void*)&watchThread, pData);
  if(rc != 0) {
		errmsg.LogError(0, RS_RET_ERR, "error: could not create thread, rc=%d", rc);
		ABORT_FINALIZE(RS_RET_ERR);
  }

CODE_STD_FINALIZERnewActInst
	cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst


BEGINdbgPrintInstInfo
CODESTARTdbgPrintInstInfo
ENDdbgPrintInstInfo


BEGINtryResume
CODESTARTtryResume
ENDtryResume

static char* readOpenShiftEnvVar(char* gearUuid, char* varName) {
  rsRetVal iRet = RS_RET_OK;

  // using snprintf this way, it will return the # of bytes needed to store
  // the entire formatting string (excluding the null terminator)
  size_t needed = snprintf(NULL, 0, "/var/lib/openshift/%s/.env/%s", gearUuid, varName) + 1;

  char* filename;
  CHKmalloc(filename = malloc(needed));
  snprintf(filename, needed, "/var/lib/openshift/%s/.env/%s", gearUuid, varName);

  FILE* fp = fopen(filename, "r");

  off_t size = 0;
  CHKiRet(getFileSize((uchar*)filename, &size));

  char* data = NULL;
  CHKmalloc(data = malloc(size));

  if(fgets(data, size, fp) == NULL) {
    // there was an error reading the file
    free(data);
    data = NULL;
  }

  fclose(fp);

finalize_it:
  return data;
}


BEGINdoAction
	msg_t *pMsg;
	struct json_object *pJson, *jval;
	rsRetVal localRet;
	uid_t uid;
	gearInfo* gear;
	char* appUuid;
	char* gearUuid;
	char* namespace;
CODESTARTdoAction
	pMsg = (msg_t*) ppString[0];

	DBGPRINTF("mmopenshift: looking for !uid\n");
  localRet = jsonFind(pMsg, es_uid, &pJson);

  if(pJson != NULL) {
    DBGPRINTF("mmopenshift: found !uid\n");

    DBGPRINTF("mmopenshift: retrieving uid value\n");
    uid = json_object_get_int(pJson);
    DBGPRINTF("mmopenshift: uid=%d\n", uid);

    if(uid < pData->gearUidStart) {
      DBGPRINTF("mmopenshift: not an openshift uid\n");
      goto finalize_it;
    }

    DBGPRINTF("mmopenshift: searching uidMap for uid %d\n", uid);
    pthread_mutex_lock(&pData->lock);
    gear = hashtable_search(pData->uidMap, &uid);
    pthread_mutex_unlock(&pData->lock);

    if(NULL == gear) {
      DBGPRINTF("mmopenshift: key not found\n");

      DBGPRINTF("mmopenshift: alloc for gearInfo\n");
      CHKmalloc(gear = malloc(sizeof(gearInfo)));

      DBGPRINTF("mmopenshift: getpwuid\n");
      struct passwd* pwdata = getpwuid(uid);

      gearUuid = pwdata->pw_name;

      //NOTE: readOpenShiftEnvVar returns memory that was malloc'd
      appUuid = readOpenShiftEnvVar(gearUuid, "OPENSHIFT_APP_UUID");
      namespace = readOpenShiftEnvVar(gearUuid, "OPENSHIFT_NAMESPACE");

      // fill in the gearInfo data
      // gearUuid
      CHKmalloc(gear->gearUuid = malloc(strlen(gearUuid) + 1));
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
      CHKmalloc(keybuf = malloc(sizeof(uid_t)));
      *keybuf = uid;

      DBGPRINTF("mmopenshift: adding to hash\n");
      pthread_mutex_lock(&pData->lock);
      hashtable_insert(pData->uidMap, keybuf, gear);
      pthread_mutex_unlock(&pData->lock);
    } else {
      DBGPRINTF("mmopenshift: found key in hash\n");

      appUuid = gear->appUuid;
      gearUuid = gear->gearUuid;
      namespace = gear->namespace;
    }

    // reset pJson to point at the root of the message's json object
    pJson = pMsg->json;

    jval = json_object_new_string(appUuid);
    json_object_object_add(pJson, "appUuid", jval);

    jval = json_object_new_string(gearUuid);
    json_object_object_add(pJson, "gearUuid", jval);

    jval = json_object_new_string(namespace);
    json_object_object_add(pJson, "appNamespace", jval);
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
ENDqueryEtryPt



BEGINmodInit()
CODESTARTmodInit
	*ipIFVersProvided = CURR_MOD_IF_VERSION; /* we only support the current interface specification */
CODEmodInit_QueryRegCFSLineHdlr
	DBGPRINTF("mmopenshift: module compiled with rsyslog version %s.\n", VERSION);
	CHKiRet(objUse(errmsg, CORE_COMPONENT));

  // initialize estring for !uid json path
  es_uid = es_newStrFromCStr("!uid", 4);
ENDmodInit
