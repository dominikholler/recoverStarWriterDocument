#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>

/* see 
 * http://svn.abisource.com/abiword/trunk/plugins/sdw/xp/ie_imp_StarOffice.cpp
 * http://svn.abisource.com/abiword/trunk/plugins/sdw/xp/ie_imp_StarOffice.h
 * http://svn.abisource.com/abiword/trunk/plugins/sdw/xp/sdw_cryptor.cpp
 * http://svn.abisource.com/abiword/trunk/plugins/sdw/xp/sdw_cryptor.h
 */

/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  
 * 02110-1301 USA.
 */


#define error(fmt, ...) fprintf(stderr, "Error: %s: %d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define info printf

#define SWGF_HAS_PASSWD 0x0008 // Stream is password protected

#define maxPWLen 16
#define TRUE 1
#define FALSE 0

static const uint8_t gEncode[] =
{ 0xab, 0x9e, 0x43, 0x05, 0x38, 0x12, 0x4d, 0x44,
  0xd5, 0x7e, 0xe3, 0x84, 0x98, 0x23, 0x3f, 0xba };

void Encrypt(const char* aEncrypted, char* aBuffer, uint32_t aLen, const char* mPassword) {
  size_t nCryptPtr = 0;
  uint8_t cBuf[maxPWLen];
  uint8_t* p = cBuf;
  memcpy(cBuf, mPassword, maxPWLen);

  if (!aLen)
    aLen = strlen(aEncrypted);

  while (aLen--) {
    *aBuffer++ = *aEncrypted++ ^ ( *p ^ ((uint8_t) ( cBuf[ 0 ] * nCryptPtr )) );
    *p += ( nCryptPtr < (maxPWLen-1) ) ? *(p+1) : cBuf[ 0 ];
    if( !*p ) *p += 1;
    p++;
    if( ++nCryptPtr >= maxPWLen ) {
      nCryptPtr = 0;
      p = cBuf;
    }
  }
}

int SetPassword(const char* aPassword, const uint8_t mFilePass[maxPWLen], const char* needle) {
  // Set the new password
  char pw[maxPWLen];
  char mPassword[maxPWLen];
  memcpy(pw, aPassword, maxPWLen);

  // the password needs to be encrypted
  memcpy(mPassword, gEncode, maxPWLen);
  Encrypt(pw, mPassword, maxPWLen, mPassword);

  // Check password if we have valid date and/or time
  {
    char testString[maxPWLen+1];
    char lNeedle[maxPWLen+1];
    memcpy(lNeedle, needle, maxPWLen+1);
    Encrypt(lNeedle, testString, maxPWLen, mPassword);
    if (memcmp(testString, mFilePass, maxPWLen) != 0) {
      return FALSE; // wrong password
    }
  }
  return TRUE;
}

void addCharToTable(char* table, int tableSize, char charToAdd, int* index)
{
  if (*index < tableSize)
  {
    table[*index] = charToAdd;
    (*index)++;
  }
  else
  {
    error("index out of bounds");
  }
}

void initTable(char* table, int tableSize)
{
  int c;
  int index=0;
#define TABLE_SIZE (1+26+26+10)
  table[index++] = ' ';
  /* A-Z */
  for(c=0x41; c<=0x5a; c++)
  {
    addCharToTable(table, tableSize, c, &index);
  }
  /* a-z */
  for(c=0x61; c<=0x7a; c++)
  {
    addCharToTable(table, tableSize, c, &index);
  }
  /* 0-9 */
  for(c=0x30; c<=0x39; c++)
  {
    addCharToTable(table, tableSize, c, &index);
  }
}

#ifdef _OPENMP

/* multi core optimized */
void recover(const uint32_t nDate, const uint32_t nTime, const uint8_t cPasswd[maxPWLen])
{
  {
    int i0;
    volatile int tries = 0;
    char table[TABLE_SIZE];
    char needle[maxPWLen+1];
    info("MAX_TRY_LEN: %d\n", MAX_TRY_LEN);
    sprintf(needle, "%08x%08x", nDate, nTime);
    initTable(table, TABLE_SIZE);
#pragma omp parallel for
    for (i0 = 0; i0 < TABLE_SIZE; ++i0)
    {
      /* if compiled with OpenMP, worker threads starts here */
      int i1,i2,i3,i4,i5,i6,i7,i8,i9,i10,i11,i12,i13,i14,i15;
      int ltries=0;
      char lguess[maxPWLen+1];
      strcpy(lguess, "                ");
      lguess[0] = table[i0];
      info("i%2d: starting with index: %2d: %s\n", 0, i0, lguess);
#define nestedFor(N) for (i##N = 0; i##N < TABLE_SIZE; ++ i##N ) {\
  lguess[N] = table[i##N];
#define nestedFor_i(N) nestedFor(N) \
 info("i%2d: starting with index: %2d: %s\n", N, i##N, lguess);

#if MAX_TRY_LEN > 1
nestedFor(1)
#endif

#if MAX_TRY_LEN > 2
nestedFor(2)
#endif

#if MAX_TRY_LEN > 3
nestedFor(3)
#endif

#if MAX_TRY_LEN > 4
nestedFor(4)
#endif

#if MAX_TRY_LEN > 5
nestedFor(5)
#endif

#if MAX_TRY_LEN > 6
nestedFor(6)
#endif

#if MAX_TRY_LEN > 7
nestedFor(7)
#endif

#if MAX_TRY_LEN > 8
nestedFor(8)
#endif

#if MAX_TRY_LEN > 9
nestedFor(9)
#endif

#if MAX_TRY_LEN > 10
nestedFor(10)
#endif

#if MAX_TRY_LEN > 11
nestedFor(11)
#endif

#if MAX_TRY_LEN > 12
nestedFor(12)
#endif

#if MAX_TRY_LEN > 13
nestedFor(13)
#endif

#if MAX_TRY_LEN > 14
nestedFor(14)
#endif

#if MAX_TRY_LEN > 15
nestedFor(15)
#endif

      if (SetPassword(lguess, cPasswd, needle))
    {
      printf("%s\n",lguess);
      exit(EXIT_SUCCESS);
    }
  ltries++;

#if MAX_TRY_LEN > 15
}
#endif

#if MAX_TRY_LEN > 14
}
#endif

#if MAX_TRY_LEN > 13
}
#endif

#if MAX_TRY_LEN > 12
}
#endif

#if MAX_TRY_LEN > 11
}
#endif

#if MAX_TRY_LEN > 10
}
#endif

#if MAX_TRY_LEN > 9
}
#endif

#if MAX_TRY_LEN > 8
}
#endif

#if MAX_TRY_LEN > 7
}
#endif

#if MAX_TRY_LEN > 6
}
#endif

#if MAX_TRY_LEN > 5
}
#endif

#if MAX_TRY_LEN > 4
}
#endif

#if MAX_TRY_LEN > 3
}
#endif

#if MAX_TRY_LEN > 2
}
#endif

#if MAX_TRY_LEN > 1
}
#endif

#pragma omp atomic
tries+=ltries;
} /* 0 */
printf("tries: %d\n", tries);
  }

}

#else /* _OPENMP */

/* single core optimized */
void recover(const uint32_t nDate, const uint32_t nTime, const uint8_t cPasswd[maxPWLen])
{

  {
    int i0,i1,i2,i3,i4,i5,i6,i7,i8,i9,i10,i11,i12,i13,i14,i15;
    long long tries = 0;
    char table[TABLE_SIZE];
    char needle[maxPWLen+1];
    char guess[maxPWLen+1];
    strcpy(guess, "                ");
    sprintf(needle, "%08x%08x", nDate, nTime);
    initTable(table, TABLE_SIZE);

#define nestedFor(N) for (i##N = 0; i##N < TABLE_SIZE; ++ i##N ) {\
  guess[N] = table[i##N];

  nestedFor(15)

  nestedFor(14)

  nestedFor(13)

  nestedFor(12)

  nestedFor(11)

  nestedFor(10)

  nestedFor(9)

  nestedFor(8)

  nestedFor(7)

  nestedFor(6)
      printf("%lld: '%s'\n",tries, guess);

  nestedFor(5)

  nestedFor(4)

  nestedFor(3)

  nestedFor(2)

  nestedFor(1)

  nestedFor(0)

      if (SetPassword(guess, cPasswd, needle))
    {
      printf("%lld: '%s': SUCCESS\n",tries, guess);
      exit(EXIT_SUCCESS);
    }
  tries++;

}

}

}

}

}

}

}

}

}

}

}

}

}

}

}

} 
  }
}
#endif /* _OPENMP */


int main(int argc, const char* argv[])
{
  /* per StarWriterDocument globals */
  uint8_t cPasswd[maxPWLen]; // password verification data
  uint32_t nDate;
  uint32_t nTime;

  {
    const char* inputFilePath;
    FILE *inputFile;
    uint8_t cLen;
    uint16_t nVersion;
    uint16_t nFileFlags;
    int32_t nDocFlags;
    uint32_t nRecSzPos;
    int32_t nDummy;
    uint16_t nDummy16; // actually 2x dummy8
    uint8_t cRedlineMode; // should actually be an enum, see sw/inc/redlenum.hxx#L83
    uint8_t nCompatVer;


    uint8_t cSet; // the encoding to use
    uint8_t cGui;

    static const char sw3hdr[] = "SW3HDR";
    static const char sw4hdr[] = "SW4HDR";
    static const char sw5hdr[] = "SW5HDR";
    char header[7];


    if (argc < 2)
    {
      error("argc < 2");
      return EXIT_FAILURE;
    }

    inputFilePath=argv[1];
    inputFile=fopen(inputFilePath, "rb");
    if ( inputFile == NULL)
    {
      error("inputFile == NULL");
      return EXIT_FAILURE;
    }

    if ( fread(header, 7, 1, inputFile) != 1)
    {
      error("Can not read header");
      return EXIT_FAILURE;
    }
    if (memcmp(header, sw3hdr, sizeof(sw3hdr)) != 0 &&
        memcmp(header, sw4hdr, sizeof(sw4hdr)) != 0 &&
        memcmp(header, sw5hdr, sizeof(sw5hdr)) != 0)
    {
      error("wrong magic");
      return EXIT_FAILURE;
    }

#define readVar(var)  if ( fread(&var, sizeof(var),1, inputFile) != 1 )\
    {\
      error("reading " #var);\
      return EXIT_FAILURE;\
    }

    readVar(cLen);
    readVar(nVersion);
    readVar(nFileFlags);
    readVar(nDocFlags);
    readVar(nRecSzPos);
    readVar(nDummy);
    readVar(nDummy16);
    readVar(cRedlineMode);
    readVar(nCompatVer);
    /* printf("SDW: clen %i nversion %i fileflags %i docflags %i recszpos %i readlinemode %i compatver %i\n",
       cLen, nVersion, nFileFlags, nDocFlags, nRecSzPos, cRedlineMode, nCompatVer); */

    if ( !(SWGF_HAS_PASSWD | nFileFlags))
    {
      error("stream is not password protected");
      return EXIT_FAILURE;
    }

    if ( fread(cPasswd, 16, 1, inputFile) != 1)
    {
      error("Can not read cPasswd");
      return EXIT_FAILURE;
    }

    readVar(cSet);
    readVar(cGui);
    readVar(nDate);
    if ( !(nDate))
    {
      error("date information is missing");
      return EXIT_FAILURE;
    }
    readVar(nTime);
    if ( !(nTime))
    {
      error("time information is missing");
      return EXIT_FAILURE;
    }

    fclose(inputFile);
  }


  recover(nDate, nTime, cPasswd);
  
  return EXIT_FAILURE;
}

