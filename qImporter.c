/**
 * qImporter.c
 * uses:
 *  libcurl3-dev
 *  libmysqlclient
 * 
 * build with:
 *  cc -o qImporter -O2 -Wall qImporter.c -L/usr/lib64/mysql/ -lcurl -lmysqlclient
 * 
 * $Id$
 *
 **/

//#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <locale.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <curl/curl.h>
#include <mysql/mysql.h>

typedef struct
{ char  splunkCredentials[61];
  char  splunkSourceType[61];
  char  splunkEarliest[21];
  char  splunkLatest[21];
  char  splunkSearchHead[11];
  char  splunkSearchFrmt[251];
  char  mysqlHost[81];
  char  mysqlUser[41];
  char  mysqlPsswd[41];
  char  emailRecipients[101];
} iniStruct;

typedef struct
{ const char *filename;
  FILE *stream;
} resFile;

iniStruct *ini;
char      *search;
int       rowCount = 0;

/* get splunk & mysql credentials/settings, email recipients from ini file */
iniStruct *getIni(void)
{ FILE *fp;
  static char path[256];
  char        *iniFile = "qImporter.ini";
  iniStruct   *ret = malloc(sizeof(iniStruct));

  readlink("/proc/self/exe", path, sizeof(path));
  *(path + (strlen(path) - strlen(strrchr(path, '/')) + 1)) = '\0';
  
  strcat(path, iniFile);
  if(!(fp = fopen(path, "r")))  
  { perror("ERROR opening ini file");
    exit(errno);
  }
  if(!(fscanf(fp, "%s %s %s %s %s\n",
              ret->splunkCredentials,
              ret->splunkSourceType,
              ret->splunkEarliest,
              ret->splunkLatest,
              ret->splunkSearchHead)))
  { perror("ERROR reading ini file");
    exit(errno);
  }
  if(!(fscanf(fp, "%[^\n]", 
              ret->splunkSearchFrmt)))
  { perror("ERROR reading ini file");
    exit(errno);
  }
  if(!(fscanf(fp, "%s %s %s\n",
              ret->mysqlHost,
              ret->mysqlUser,
              ret->mysqlPsswd)))
  { perror("ERROR reading ini file");
    exit(errno);
  }
  if(!(fscanf(fp, "%s\n",
              ret->emailRecipients)))
  { perror("ERROR reading ini file");
    exit(errno);
  }

  fclose(fp);
  return ret;
}

/* send an email */
int sendmail(const char *to, const char *from, const char *subject, const char *message)
{ int  retval = -1;
  FILE *mailpipe = popen("/usr/lib/sendmail -t", "w");
 
  if(mailpipe != NULL) 
  { fprintf(mailpipe, "To: %s\n", to);
    fprintf(mailpipe, "From: %s\n", from);
    fprintf(mailpipe, "Subject: %s\n\n", subject);
    fwrite(message, 1, strlen(message), mailpipe);
    fwrite("\n.\n", 1, 2, mailpipe);
    pclose(mailpipe);
    retval = 0;
  }
  else
    perror("Failed to invoke sendmail");
  
  return retval;
}


/* TopControl logger */
#define HOST     "localhost"
#define PORT      11000
#define CHECKER   "MySQL-Quotemeter-Importer"

#define h_addr h_addr_list[0]

void log2tweety(char *stat, char *reason)
{ int    sockfd;
  struct sockaddr_in serv_addr;
  struct hostent *server;
  char   *tweetyLog;

  /* Open socket connection to Tweety */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(sockfd < 0) 
  { perror("ERROR opening socket");
    exit(errno);
  }
  if((server = gethostbyname(HOST)) == NULL)
  { fprintf(stderr,"ERROR, no such host\n");
    exit(0);
  }
    
  bzero((char *) &serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  bcopy((char *)server->h_addr, 
        (char *)&serv_addr.sin_addr.s_addr,
        server->h_length);
  serv_addr.sin_port = htons(PORT);
  if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
  { perror("ERROR connecting");
    exit(errno);
  }
  
  tweetyLog = malloc(151 + strlen(reason));
  sprintf(tweetyLog,
          "%s.LogChecker.Result = bool %s %s.LogChecker.Reason = str \"%s\"\n",
          CHECKER,
          stat,
          CHECKER,
          reason);
          
  if((write(sockfd, tweetyLog, strlen(tweetyLog))) < 0)
  { perror("ERROR writing to socket");
    exit(errno);
  }
  
  free(tweetyLog);
	close(sockfd);

  if(!strcmp(stat, "false"))
    sendmail(ini->emailRecipients, 
             "quotemeter_importer@interactivedata.com",
             "Quotemeter Importer Status",
             reason);

  exit((strcmp(stat, "true") ? 0 : errno));
}

/* Converts an integer value to its hex character*/
char to_hex(char code)
{ static char hex[] = "0123456789abcdef";
  return hex[code & 15];
}

/* Returns a url-encoded version of str */
char *url_encode(char *str)
{ char *pstr = str, *buf = malloc(strlen(str) * 3 + 1), *pbuf = buf;
  
  while (*pstr)
  { if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~') 
      *pbuf++ = *pstr;
    else if (*pstr == ' ') 
      *pbuf++ = '+';
    else 
      *pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
    pstr++;
  }
  *pbuf = '\0';
  return buf;
}

static size_t myWrite(void *buffer, size_t size, size_t nmemb, void *stream)
{
  resFile *out=(resFile *)stream;
  if(out && !out->stream)
  { /* open file for writing */ 
    out->stream=fopen(out->filename, "wb");
    if(!out->stream)
      return -1; /* failure, can't open file to write */ 
  }
  return fwrite(buffer, size, nmemb, out->stream);
}

void execRest(void)
{ CURL      *curl;
  char      *urlFrmt = "https://splunkclsh0%dnja.fdsg.factset.com:8291/servicesNS/admin/webintelligence/search/jobs/export";
  CURLcode  res;
  char      *param;
  char      *url;
  resFile   myRes = { "/tmp/result.csv",
                      NULL
                    };

  search = malloc(strlen(ini->splunkSearchFrmt) + strlen(ini->splunkSourceType));
  sprintf(search, ini->splunkSearchFrmt, ini->splunkSourceType);
  param = malloc(strlen(search) + 
                 strlen(ini->splunkEarliest) + 
                 strlen(ini->splunkLatest) +
                 101);
  url = malloc(strlen(urlFrmt));
  sprintf(url, urlFrmt, atoi(ini->splunkSearchHead));
                 
  curl = curl_easy_init();
  if(curl)
  { curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERPWD, ini->splunkCredentials);

    sprintf(param,
            "search=search+%s&earliest_time=%s&latest_time=%s&output_mode=csv",
            url_encode(search),
            url_encode(ini->splunkEarliest),
            url_encode(ini->splunkLatest));
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, param);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, myWrite);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &myRes);

    /* For HTTPS */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
     
    if((res = curl_easy_perform(curl)))
    { printf("Curl request failed: %d\n", res);
      log2tweety("false", "Curl request failed");
    }
    curl_easy_cleanup(curl);

    free(param);
    free(search);
    if(myRes.stream)
      fclose(myRes.stream);
  }

}

#define RET { *list = _list; free(copy); return; }

void explode(char *src, const char *tokens, char ***list, size_t *len)
{ if(src == NULL || list == NULL || len == NULL)
    return;

  char *str, *copy, **_list = NULL, **tmp;
  *list = NULL;
  *len  = 0;

  if((copy = strdup(src)) == NULL)
    return;

  if((str = strsep(&copy, tokens)) == NULL)
    RET;

  if((_list = realloc(NULL, sizeof *_list)) == NULL)
    RET;
    
  if((_list[*len] = strdup(str)) == NULL)
    RET;
  (*len)++;

  while((str = strsep(&copy, tokens)))
  { if((tmp = realloc(_list, (sizeof *_list) * (*len + 1))) == NULL)
      RET;
    _list = tmp;

    if((_list[*len] = strdup(str)) == NULL)
      RET;
    (*len)++;
  }

  RET;
}

/* removes leading und trailing occurrences of 'c' in string 's' */
char* trim(char *s, char c)
{ char *end = s + strlen(s)-1;

  while(*s && *s == c)
    *s++ = 0;

  while(*end == c)
    *end-- = 0;
  return s;
}

int get_line(FILE *fp, char *buffer, size_t buflen)
{ char *end = buffer + buflen - 1;
  char *dst = buffer;
  int c;
  
  while ((c = getc(fp)) != EOF && c != '\n' && dst < end)
    if(c != '"') *dst++ = c;
  *dst = '\0';
  return((c == EOF && dst == buffer) ? EOF : dst - buffer);
}

long chklen(char *str, long len)
{ int l;
  
  l = strlen(str);
  return((l>len) ? len : l);
}

char *getYear(void)
{ char *currY = malloc(sizeof(char)*5);
  struct tm *tm;
  time_t    now;
  
  currY = malloc(sizeof(char) * 5);
  now = time(NULL);
  tm = localtime(&now);
  tm->tm_mday--;                                      /* yesterday    */
  mktime(tm);                                         /* Normalise tm */
  strftime(currY, sizeof(currY), "%Y", tm);  
  return(currY);
}
  
void processResult(void)
{ FILE          *fp;
  char          *line  = malloc(512 * sizeof(char));
  char          **list, dtDB[31], *stmt0, *currYear;
  size_t        i, len;
  MYSQL	        *conn;
  const char    *sPS   = "INSERT INTO `db_quotemeter`.`tblQuoteUsageSplunk_%4s` (Symbol, AccountNumber, UserID, DepartmentID, Exchange, TotalUsage, OptionsChainCount, SubMarket, ProNonProStatus, AppID, UsageDate, CSPAccountNumber, ExtraValue1, ExtraValue2) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
  const char    *stmt1 = "START TRANSACTION";
  const char    *stmt2 = "COMMIT";
  const char    *stmt3 = "ROLLBACK";
  MYSQL_STMT    *stmt;
  MYSQL_BIND    param[14];
  unsigned long l[14], val[3];
  struct tm     when;

   /* Open MySQL connection and prepare insert statement */
  conn = mysql_init(NULL);
  if (conn == NULL)
  { printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
    log2tweety("false", "MySQL open connection failed");
  }

  if (mysql_real_connect(conn, ini->mysqlHost, ini->mysqlUser, ini->mysqlPsswd, "db_quotemeter", 3306, NULL, CLIENT_MULTI_STATEMENTS) == NULL)
  { printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
    log2tweety("false", "MySQL open connection failed");
  }
  
  if((stmt = mysql_stmt_init(conn)) == NULL)
  { printf("Unable to create new session: Could not init statement handle\n");
    log2tweety("false", "Unable to create new session: Could not init statement handle");
  }
  
  /* get year and prepare the query statement */
  stmt0 = malloc(strlen(sPS) + 5);
  currYear = getYear();
  sprintf(stmt0, sPS, getYear());
  free(currYear);
  
  //printf("query: %s\n", stmt0);
  //exit(0);

  if(mysql_stmt_prepare(stmt, stmt0, strlen(stmt0)) != 0)
  { printf("Unable to create new session: Could not prepare statement\n");
    log2tweety("false", "Unable to create new session: Could not prepare statement");
  }
  free(stmt0);
  
  memset(param, 0, sizeof(param));  

  /* open result file */
  if(!(fp = fopen("/tmp/result.csv", "r")))
  { perror("ERROR opening results file");
    log2tweety("false", "Unable to open results file");
  }

  /* skip title row */
  get_line(fp, line, 512);

  /* start transaction */
  if (mysql_real_query(conn, stmt1, strlen(stmt1)))
  { printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
    log2tweety("false", "Start transaction failed");
  }

  while(get_line(fp, line, 512) > 0)
  { explode(line, ";", &list, &len);

    /*** check number of returned fields ***/
    if(len < (size_t)12) continue;
    
    /*** prepare table fields ***/

    /* Symbol */
    param[0].buffer_type = MYSQL_TYPE_STRING;
    param[0].buffer = list[10];
//    l[0] = strlen(list[10]);
    l[0] = chklen(list[10], 25);
    param[0].buffer_length = l[0];
    param[0].length = &l[0];
    
    /* AccountNumber */
    param[1].buffer_type = MYSQL_TYPE_STRING;
    param[1].buffer = list[11];
    l[1] = chklen(list[11], 20);
    param[1].buffer_length = l[1];
    param[1].length = &l[1];
     
    /* UserID */
    param[2].buffer_type = MYSQL_TYPE_STRING;
    param[2].buffer = list[3];
    l[2] = chklen(list[3], 20);
    param[2].buffer_length = l[2];
    param[2].length = &l[2];

    /* DepartmentID */
    param[3].buffer_type = MYSQL_TYPE_STRING;
    param[3].buffer = list[2];
    l[3] = chklen(list[2], 20);
    param[3].buffer_length = l[3];
    param[3].length = &l[3];

    /* Exchange */
    param[4].buffer_type = MYSQL_TYPE_STRING;
    param[4].buffer = list[4];
    l[4] = chklen(list[4], 20);
    param[4].buffer_length = l[4];
    param[4].length = &l[4];
    
    /* TotalUsage */
    param[5].buffer_type = MYSQL_TYPE_LONG;
    val[0] = atol(list[5]);
    param[5].buffer = &val[0];
    l[5] = 11;
    param[5].buffer_length = l[5];
    param[5].length = &l[5];
    
    /* OptionsChainCount */
    param[6].buffer_type = MYSQL_TYPE_LONG;
    val[1] = atol(list[6]);
    param[6].buffer = &val[1];
    l[6] = 11;
    param[6].buffer_length = l[6];
    param[6].length = &l[6];
    
    /* SubMarket */
    param[7].buffer_type = MYSQL_TYPE_LONG;
    val[2] = atol(list[9]);
    param[7].buffer = &val[2];
    l[7] = 11;
    param[7].buffer_length = l[7];
    param[7].length = &l[7];
    
    /* ProNonProStatus */
    param[8].buffer_type = MYSQL_TYPE_STRING;
    param[8].buffer = list[7];
    l[8] = chklen(list[7], 40);
    param[8].buffer_length = l[8];
    param[8].length = &l[8];
    
    /* AppID */
    param[9].buffer_type = MYSQL_TYPE_STRING;
    param[9].buffer = list[8];
    l[9] = chklen(list[8], 20);
    param[9].buffer_length = l[9];
    param[9].length = &l[9];

    /* UsageDate */
    strptime(list[1], "%m/%d/%Y %H:%M:%S", &when);
    strftime(dtDB, 21, "%Y-%m-%d %H:%M:%S", &when);

    param[10].buffer_type = MYSQL_TYPE_STRING;
    param[10].buffer = dtDB;
    l[10] = strlen(dtDB);
    param[10].buffer_length = l[10];
    param[10].length = &l[10];

    /* CSPAccountNumber */
    param[11].buffer_type = MYSQL_TYPE_STRING;
    param[11].buffer = list[11];
    l[11] = chklen(list[11], 20);
    param[11].buffer_length = l[11];
    param[11].length = &l[11];

    /* ---- extra values ---- */
    if(len > (size_t)12)
    { /* ExtraValue1 */
      param[12].buffer_type = MYSQL_TYPE_STRING;
      param[12].buffer = list[12];
      l[12] = chklen(list[12], 50);
      param[12].buffer_length = l[12];
      param[12].length = &l[12];

      if(len > (size_t)13)
      { /* ExtraValue2 */
        param[13].buffer_type = MYSQL_TYPE_STRING;
        param[13].buffer = list[13];
        l[13] = chklen(list[13], 50);
        param[13].buffer_length = l[13];
        param[13].length = &l[13];
      }
      else
      { param[13].buffer_type = MYSQL_TYPE_STRING;
        param[13].buffer = "";
        l[13] = strlen("");
        param[13].buffer_length = l[13];
        param[13].length = &l[13];
      }
    }
    else
    { param[12].buffer_type = MYSQL_TYPE_STRING;
      param[12].buffer = "";
      l[12] = strlen("");
      param[12].buffer_length = l[12];
      param[12].length = &l[12];
      
      param[13].buffer_type = MYSQL_TYPE_STRING;
      param[13].buffer = "";
      l[13] = strlen("");
      param[13].buffer_length = l[13];
      param[13].length = &l[13];
    }

    if(mysql_stmt_bind_param(stmt, param) != 0)
    { printf("Unable to create new session: Could not bind parameters - %s\n", mysql_stmt_error(stmt));
      log2tweety("false", "Unable to create new session: Could not bind parameters");
    }

    if(mysql_stmt_execute(stmt) != 0)
    { printf("Unable to create new session: Could not execute statement - %s\n", mysql_stmt_error(stmt));
      log2tweety("false", "Unable to create new session: Could not execute statement");
    }

    if(!((++rowCount) % 1000))
      printf("Processing row: %d\n", rowCount);
    
    /* free list */
    for(i = 0; i < len; ++i)
      free(list[i]);
    free(list);
  }

  /* commit transaction */
  if (mysql_real_query(conn, stmt2, strlen(stmt2)))
  { printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
    mysql_real_query(conn, stmt3, strlen(stmt3));
    log2tweety("false", "Commit transaction failed. Rollback.");
  }

  printf("Processing row: %d\n", rowCount);
  
  fclose(fp);
  unlink("/tmp/result.csv");
  
  mysql_stmt_free_result(stmt);
  mysql_stmt_close(stmt);
 	mysql_close(conn);
  free(line);
}

int main(void)
{ char *message = malloc(101 * sizeof(char));

  ini = getIni();
  execRest();
  processResult();

  sprintf(message, "%d rows successful inserted.", rowCount);
  //log2tweety("true", message);

  free(message);
  free(ini);
  
  return(0);
}
