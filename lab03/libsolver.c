# include <stdio.h>
#include <sys/types.h>
# include "shuffle.h"
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>


typedef int (*function_handle)(int);

typedef struct {
    int code_num;
    int got_offset;
} GOT_OFFSET;

int init(){
    GOT_OFFSET table [] = { { 1,0x18b30 },{ 2,0x180c0 },{ 3,0x18b40 },{ 4,0x18048 },{ 5,0x18ae8 },{ 6,0x18300 },{ 7,0x18db0 },{ 10,0x17b98 },{ 15,0x18618 },{ 20,0x17e08 },{ 22,0x17e10 },{ 23,0x188c8 },{ 25,0x18868 },{ 26,0x17da0 },{ 27,0x188b8 },{ 28,0x17d98 },{ 30,0x18b78 },{ 33,0x180d8 },{ 38,0x18af8 },{ 43,0x18390 },{ 44,0x18e58 },{ 45,0x18368 },{ 47,0x182d0 },{ 48,0x18d90 },{ 50,0x185f0 },{ 56,0x18648 },{ 57,0x17b68 },{ 58,0x185c8 },{ 61,0x17f48 },{ 62,0x189e0 },{ 67,0x17f08 },{ 70,0x18200 },{ 71,0x18c90 },{ 73,0x18c60 },{ 75,0x18c70 },{ 76,0x181d8 },{ 77,0x18bf8 },{ 81,0x18fa8 },{ 84,0x184c8 },{ 87,0x18f28 },{ 92,0x17ce0 },{ 95,0x18730 },{ 96,0x17c58 },{ 97,0x18710 },{ 101,0x18820 },{ 102,0x17d58 },{ 108,0x17c98 },{ 109,0x18758 },{ 111,0x189d0 },{ 112,0x17f30 },{ 113,0x189c8 },{ 114,0x17f18 },{ 115,0x18998 },{ 117,0x18970 },{ 120,0x18d20 },{ 124,0x18c48 },{ 126,0x18c20 },{ 129,0x181b0 },{ 132,0x18f70 },{ 133,0x184a8 },{ 134,0x18f50 },{ 139,0x184e8 },{ 141,0x17c80 },{ 142,0x18750 },{ 144,0x18740 },{ 145,0x17cf8 },{ 147,0x17cc8 },{ 149,0x17d10 },{ 152,0x189b0 },{ 153,0x17f10 },{ 154,0x18988 },{ 155,0x17ef8 },{ 157,0x17ed8 },{ 158,0x18a10 },{ 159,0x17f70 },{ 160,0x181f0 },{ 163,0x18c18 },{ 164,0x181c8 },{ 167,0x18cc0 },{ 169,0x18ca0 },{ 171,0x18fc0 },{ 173,0x18fb0 },{ 175,0x17a40 },{ 176,0x18538 },{ 179,0x18f40 },{ 180,0x17c70 },{ 182,0x17cf0 },{ 183,0x18798 },{ 185,0x18780 },{ 186,0x17d18 },{ 189,0x187b0 },{ 199,0x18a38 },{ 200,0x17b30 },{ 201,0x18620 },{ 203,0x18608 },{ 206,0x17a90 },{ 208,0x17a78 },{ 212,0x18df0 },{ 218,0x18d10 },{ 220,0x18088 },{ 221,0x18b10 },{ 222,0x18060 },{ 224,0x17fc8 },{ 226,0x17fb8 },{ 230,0x17de8 },{ 234,0x17d50 },{ 235,0x18800 },{ 238,0x17d30 },{ 239,0x18848 },{ 240,0x18600 },{ 242,0x18588 },{ 244,0x18578 },{ 248,0x18558 },{ 249,0x17a60 },{ 254,0x18268 },{ 257,0x18d58 },{ 259,0x18d30 },{ 260,0x18a70 },{ 261,0x17fb0 },{ 262,0x18a60 },{ 265,0x18008 },{ 269,0x18038 },{ 271,0x17d60 },{ 272,0x18810 },{ 273,0x17d48 },{ 278,0x18840 },{ 280,0x17a80 },{ 283,0x18570 },{ 284,0x17a70 },{ 285,0x18550 },{ 286,0x17a58 },{ 287,0x185b0 },{ 290,0x18d08 },{ 291,0x182c0 },{ 293,0x182a8 },{ 299,0x18260 },{ 300,0x17bc0 },{ 304,0x17bd8 },{ 307,0x18610 },{ 311,0x17e80 },{ 313,0x17e78 },{ 315,0x17de0 },{ 317,0x17dd8 },{ 318,0x188a8 },{ 320,0x18168 },{ 321,0x18b98 },{ 326,0x18058 },{ 328,0x18050 },{ 329,0x18ae0 },{ 330,0x18ec0 },{ 331,0x18430 },{ 332,0x18ea8 },{ 333,0x18410 },{ 334,0x18dd8 },{ 337,0x18328 },{ 338,0x18dd0 },{ 339,0x18320 },{ 340,0x186c0 },{ 351,0x18920 },{ 355,0x188b0 },{ 360,0x18af0 },{ 366,0x18b28 },{ 367,0x18098 },{ 368,0x18b08 },{ 369,0x18080 },{ 374,0x18318 },{ 375,0x18e10 },{ 377,0x18df8 },{ 380,0x17b38 },{ 391,0x17dd0 },{ 396,0x188a0 },{ 403,0x18500 },{ 406,0x18f98 },{ 407,0x183f8 },{ 408,0x18ea0 },{ 409,0x183e8 },{ 411,0x18c58 },{ 412,0x18208 },{ 413,0x18ca8 },{ 415,0x18c80 },{ 416,0x18140 },{ 418,0x18138 },{ 421,0x17f50 },{ 424,0x189e8 },{ 427,0x17e70 },{ 429,0x17e50 },{ 430,0x17cd8 },{ 432,0x17cb0 },{ 433,0x186b0 },{ 437,0x186a0 },{ 439,0x18698 },{ 440,0x184f8 },{ 443,0x18f90 },{ 446,0x183e0 },{ 448,0x183d8 },{ 450,0x18c78 },{ 451,0x18148 },{ 457,0x18108 },{ 460,0x17f40 },{ 461,0x189f0 },{ 466,0x17e58 },{ 467,0x18918 },{ 469,0x18910 },{ 470,0x186a8 },{ 473,0x17bc8 },{ 480,0x18e98 },{ 482,0x18e90 },{ 489,0x18470 },{ 492,0x18130 },{ 497,0x18b88 },{ 498,0x18180 },{ 499,0x18ba8 },{ 501,0x18580 },{ 502,0x17a68 },{ 505,0x185a0 },{ 508,0x18f80 },{ 509,0x184d8 },{ 511,0x17d40 },{ 512,0x18808 },{ 513,0x17d70 },{ 518,0x18770 },{ 519,0x17ca0 },{ 520,0x18a68 },{ 523,0x17ff0 },{ 527,0x17f28 },{ 528,0x189b8 },{ 529,0x17f20 },{ 531,0x18d38 },{ 532,0x182b0 },{ 533,0x18d18 },{ 534,0x18280 },{ 537,0x18c40 },{ 538,0x181e0 },{ 539,0x18c28 },{ 541,0x17a88 },{ 543,0x18f88 },{ 545,0x18f78 },{ 546,0x184c0 },{ 548,0x184b0 },{ 550,0x17d68 },{ 551,0x18828 },{ 556,0x17ca8 },{ 557,0x18768 },{ 558,0x17c90 },{ 561,0x189d8 },{ 562,0x17f38 },{ 563,0x189c0 },{ 566,0x17f00 },{ 567,0x18978 },{ 568,0x17ee0 },{ 569,0x18a28 },{ 571,0x18288 },{ 572,0x18c68 },{ 573,0x181f8 },{ 574,0x18c50 },{ 575,0x181e8 },{ 576,0x18c30 },{ 577,0x181d0 },{ 581,0x184b8 },{ 583,0x184a0 },{ 584,0x18f58 },{ 590,0x18760 },{ 591,0x17c88 },{ 597,0x17cc0 },{ 598,0x18778 },{ 601,0x184e0 },{ 606,0x17a30 },{ 607,0x18528 },{ 609,0x187d8 },{ 613,0x18cd0 },{ 620,0x17f78 },{ 621,0x18a00 },{ 624,0x17f98 },{ 628,0x18230 },{ 629,0x18ce8 },{ 630,0x18790 },{ 631,0x17d00 },{ 632,0x187a8 },{ 634,0x187b8 },{ 635,0x17f90 },{ 636,0x18a48 },{ 637,0x17f80 },{ 639,0x17f60 },{ 641,0x17a38 },{ 642,0x18520 },{ 646,0x187c0 },{ 648,0x187a0 },{ 650,0x18cc8 },{ 651,0x18220 },{ 657,0x18530 },{ 659,0x18510 },{ 660,0x18a30 },{ 661,0x18250 },{ 662,0x18cf8 },{ 663,0x18238 },{ 674,0x17f88 },{ 676,0x17f68 },{ 677,0x18a08 },{ 680,0x17d38 },{ 683,0x187e0 },{ 684,0x17d28 },{ 685,0x187e8 },{ 687,0x184f0 },{ 688,0x18fc8 },{ 692,0x18548 },{ 697,0x18cb0 },{ 698,0x18218 },{ 699,0x18ce0 },{ 701,0x185a8 },{ 704,0x17ab8 },{ 706,0x17ae0 },{ 707,0x18878 },{ 709,0x18858 },{ 710,0x18830 },{ 711,0x17d80 },{ 712,0x18850 },{ 716,0x18aa8 },{ 717,0x18030 },{ 718,0x18a98 },{ 719,0x18018 },{ 720,0x17fe0 },{ 726,0x182f8 },{ 728,0x182e0 },{ 729,0x18d48 },{ 738,0x17ad8 },{ 739,0x18590 },{ 741,0x17ac0 },{ 744,0x18870 },{ 748,0x18838 },{ 751,0x18ab0 },{ 753,0x18aa0 },{ 754,0x18010 },{ 756,0x18000 },{ 757,0x18a78 },{ 758,0x17fd8 },{ 760,0x18ac0 },{ 761,0x18028 },{ 762,0x18d88 },{ 764,0x18d70 },{ 766,0x18d40 },{ 769,0x18290 },{ 771,0x17b20 },{ 772,0x185d8 },{ 775,0x17b00 },{ 776,0x18298 },{ 777,0x18d28 },{ 779,0x18d50 },{ 782,0x17da8 },{ 783,0x18898 },{ 785,0x18598 },{ 786,0x17a98 },{ 787,0x185b8 },{ 788,0x17ab0 },{ 794,0x18ad0 },{ 796,0x18ad8 },{ 797,0x18040 },{ 799,0x17d78 },{ 800,0x18e00 },{ 801,0x18330 },{ 805,0x18378 },{ 807,0x18668 },{ 808,0x17b60 },{ 811,0x18b48 },{ 814,0x180b8 },{ 816,0x183a0 },{ 817,0x18e20 },{ 822,0x188d8 },{ 823,0x180d0 },{ 825,0x180a8 },{ 827,0x18090 },{ 828,0x18b20 },{ 829,0x18068 },{ 834,0x17e00 },{ 841,0x17b80 },{ 842,0x18670 },{ 847,0x17b50 },{ 849,0x17af8 },{ 850,0x18b58 },{ 851,0x180b0 },{ 852,0x18e30 },{ 853,0x18398 },{ 854,0x18e28 },{ 855,0x18388 },{ 856,0x18e08 },{ 857,0x18350 },{ 860,0x18120 },{ 862,0x180f0 },{ 864,0x180f8 },{ 865,0x18b80 },{ 866,0x17df0 },{ 870,0x18908 },{ 871,0x17e20 },{ 872,0x188f0 },{ 873,0x17e28 },{ 876,0x18628 },{ 877,0x17b58 },{ 884,0x17ba8 },{ 885,0x18678 },{ 891,0x18e88 },{ 892,0x183c0 },{ 893,0x18e68 },{ 894,0x183a8 },{ 896,0x183b0 },{ 897,0x18b00 },{ 898,0x18070 },{ 900,0x18eb8 },{ 901,0x18440 },{ 902,0x18ed0 },{ 903,0x18458 },{ 906,0x17c48 },{ 908,0x17c40 },{ 919,0x18928 },{ 920,0x18938 },{ 921,0x17e98 },{ 924,0x18bd8 },{ 925,0x18198 },{ 927,0x18190 },{ 929,0x18178 },{ 930,0x18bc0 },{ 932,0x18f18 },{ 933,0x18450 },{ 936,0x18ee8 },{ 943,0x17c50 },{ 944,0x18700 },{ 945,0x17c38 },{ 946,0x186e8 },{ 947,0x17c10 },{ 949,0x17be0 },{ 950,0x18990 },{ 952,0x18960 },{ 953,0x17ec0 },{ 954,0x18968 },{ 956,0x186e0 },{ 960,0x181b8 },{ 961,0x18be0 },{ 963,0x18be8 },{ 969,0x18948 },{ 970,0x18490 },{ 971,0x18f48 },{ 974,0x18488 },{ 977,0x18f30 },{ 981,0x18748 },{ 983,0x18728 },{ 985,0x18738 },{ 986,0x17c60 },{ 988,0x18eb0 },{ 989,0x18438 },{ 990,0x17ed0 },{ 993,0x186f0 },{ 995,0x18708 },{ 999,0x18958 },{ 1001,0x185e0 },{ 1004,0x17b08 },{ 1007,0x185d0 },{ 1008,0x17aa8 },{ 1011,0x17dc0 },{ 1012,0x18890 },{ 1013,0x17dc8 },{ 1015,0x17db8 },{ 1016,0x18880 },{ 1019,0x17d88 },{ 1021,0x18a90 },{ 1023,0x18ab8 },{ 1026,0x17fe8 },{ 1027,0x18a80 },{ 1032,0x18d68 },{ 1034,0x18d80 },{ 1035,0x182e8 },{ 1040,0x18568 },{ 1045,0x17ac8 },{ 1049,0x17eb0 },{ 1051,0x187f8 },{ 1055,0x18bb0 },{ 1056,0x18150 },{ 1059,0x18bc8 },{ 1063,0x18020 },{ 1064,0x18ac8 },{ 1067,0x17ff8 },{ 1068,0x18ee0 },{ 1069,0x18408 },{ 1071,0x18d78 },{ 1072,0x182d8 },{ 1073,0x18da0 },{ 1074,0x182a0 },{ 1082,0x17e18 },{ 1084,0x17e60 },{ 1085,0x18900 },{ 1090,0x187d0 },{ 1093,0x180e0 },{ 1095,0x18128 },{ 1097,0x18118 },{ 1098,0x18c00 },{ 1099,0x18188 },{ 1101,0x183d0 },{ 1103,0x183b8 },{ 1105,0x18380 },{ 1106,0x18e48 },{ 1107,0x18340 },{ 1110,0x181c0 },{ 1111,0x18c10 },{ 1114,0x18078 },{ 1115,0x18b18 },{ 1116,0x18508 },{ 1117,0x18fa0 },{ 1120,0x18980 },{ 1121,0x17ef0 },{ 1125,0x18228 },{ 1126,0x18c88 },{ 1128,0x18cf0 },{ 1129,0x18248 },{ 1132,0x17b70 },{ 1133,0x18658 },{ 1134,0x17b78 },{ 1136,0x17b48 },{ 1137,0x18640 },{ 1140,0x184d0 },{ 1142,0x18370 },{ 1143,0x18e38 },{ 1144,0x18338 },{ 1147,0x17ce8 },{ 1148,0x18788 },{ 1149,0x17cd0 },{ 1151,0x185e8 },{ 1152,0x17af0 },{ 1156,0x17b18 },{ 1160,0x17ec8 },{ 1163,0x18da8 },{ 1165,0x18dc8 },{ 1166,0x18308 },{ 1167,0x18db8 },{ 1169,0x18cd8 },{ 1175,0x17f58 },{ 1176,0x18a50 },{ 1179,0x17fa8 },{ 1180,0x18f60 },{ 1182,0x18f20 },{ 1184,0x17db0 },{ 1185,0x18888 },{ 1186,0x17cb8 },{ 1188,0x17d08 },{ 1189,0x187c8 },{ 1191,0x17b28 },{ 1192,0x185f8 },{ 1193,0x17b10 },{ 1194,0x18630 },{ 1198,0x18680 },{ 1200,0x18f68 },{ 1202,0x18f38 },{ 1203,0x18468 },{ 1204,0x18f08 },{ 1206,0x18ec8 },{ 1208,0x18ef0 },{ 1211,0x17c78 },{ 1212,0x186f8 },{ 1213,0x17c68 },{ 1215,0x17c28 },{ 1217,0x17bf0 },{ 1218,0x186d0 },{ 1219,0x17c18 },{ 1221,0x17e48 },{ 1225,0x17e90 },{ 1226,0x18d60 },{ 1229,0x182f0 },{ 1230,0x18110 },{ 1231,0x18b90 },{ 1232,0x180e8 },{ 1234,0x18170 },{ 1235,0x17ad0 },{ 1237,0x17aa0 },{ 1239,0x17ae8 },{ 1242,0x18460 },{ 1243,0x18f00 },{ 1246,0x18418 },{ 1247,0x18ed8 },{ 1250,0x17bd0 },{ 1251,0x18718 },{ 1253,0x18720 },{ 1254,0x17be8 },{ 1255,0x186c8 },{ 1256,0x17c08 },{ 1258,0x17fd0 },{ 1259,0x18a88 },{ 1260,0x17e30 },{ 1263,0x18d00 },{ 1264,0x18278 },{ 1266,0x18270 },{ 1268,0x182c8 },{ 1269,0x18dc0 },{ 1272,0x17a48 },{ 1273,0x18540 },{ 1276,0x17a50 },{ 1279,0x185c0 },{ 1280,0x18e60 },{ 1282,0x18e78 },{ 1283,0x187f0 },{ 1284,0x17d20 },{ 1285,0x18818 },{ 1287,0x18860 },{ 1291,0x17ba0 },{ 1293,0x17bb0 },{ 1300,0x18240 },{ 1304,0x18258 },{ 1306,0x18210 },{ 1308,0x18650 },{ 1309,0x17b40 },{ 1310,0x18a58 },{ 1312,0x18a40 },{ 1313,0x17fa0 },{ 1316,0x18a18 },{ 1317,0x18360 },{ 1318,0x18de0 },{ 1321,0x180a0 },{ 1324,0x18b68 },{ 1326,0x18b50 },{ 1331,0x18518 },{ 1332,0x17df8 },{ 1333,0x188c0 },{ 1335,0x188e8 },{ 1337,0x188d0 },{ 1338,0x17e40 },{ 1342,0x18cb8 },{ 1345,0x18638 },{ 1346,0x17b90 },{ 1347,0x18660 },{ 1348,0x17b88 },{ 1351,0x189f8 },{ 1353,0x18a20 },{ 1354,0x18358 },{ 1355,0x18de8 },{ 1356,0x18348 },{ 1359,0x18e40 },{ 1360,0x180c8 },{ 1361,0x18b60 },{ 1362,0x18100 },{ 1363,0x18b38 },{ 1365,0x18b70 },{ 1368,0x18160 },{ 1370,0x188e0 },{ 1373,0x17e68 },{ 1374,0x188f8 },{ 1377,0x17e88 },{ 1379,0x17e38 },{ 1380,0x18690 },{ 1385,0x17bb8 },{ 1386,0x186d8 },{ 1388,0x18688 },{ 1390,0x18e18 },{ 1391,0x183c8 },{ 1394,0x18e80 },{ 1395,0x18428 },{ 1396,0x18e70 },{ 1398,0x18e50 },{ 1399,0x183f0 },{ 1400,0x18310 },{ 1401,0x18d98 },{ 1406,0x182b8 },{ 1407,0x17c20 },{ 1409,0x17c00 },{ 1413,0x18930 },{ 1414,0x17eb8 },{ 1415,0x18950 },{ 1418,0x17ea0 },{ 1419,0x189a8 },{ 1421,0x17d90 },{ 1422,0x18bb8 },{ 1423,0x18158 },{ 1424,0x18ba0 },{ 1426,0x18bd0 },{ 1433,0x18ef8 },{ 1434,0x18400 },{ 1436,0x18478 },{ 1437,0x18f10 },{ 1445,0x186b8 },{ 1446,0x17bf8 },{ 1448,0x17c30 },{ 1450,0x18940 },{ 1451,0x17ea8 },{ 1454,0x189a0 },{ 1457,0x17ee8 },{ 1461,0x18c08 },{ 1463,0x18c38 },{ 1464,0x181a0 },{ 1467,0x18c98 },{ 1468,0x181a8 },{ 1469,0x18bf0 },{ 1471,0x18448 },{ 1473,0x18480 },{ 1475,0x18498 },{ 1476,0x18fb8 }} ;

    //find the process begin address and mprotect min_address and page size(max_address-min_address)
    long int basic_address;
    static long int main_min = 0, main_max = 0;
    int fd, sz;
	char buf[16384], *s = buf, *line, *saveptr;
	if((fd = open("/proc/self/maps", O_RDONLY)) < 0) errquit("get_base/open");
	if((sz = read(fd, buf, sizeof(buf)-1)) < 0) errquit("get_base/read");
	buf[sz] = 0;
	close(fd);
    int count = 1;
	while((line = strtok_r(s, "\n\r", &saveptr)) != NULL) { s = NULL;
        if(count == 5) break;
		if(strstr(line, "/chal") != NULL) {
			if(sscanf(line, "%lx-%lx ", &main_min, &main_max) != 2) errquit("get_base/main");
            if(count == 1) basic_address = main_min;
            printf("%lx-%lx\n",main_min,main_max);
		}
        count++;
	}
    printf("%lx-%lx\n",main_min,main_max);

    // Though dlopen and dlsym to find functuin actual address
    size_t GOT_Table_size = sizeof(table) / sizeof(GOT_OFFSET);
    // know the ndat'size (ndat is in the shuffle.h)
    size_t ndat_size = sizeof(ndat) / sizeof(int);
    void *handle;
    char *error;
    function_handle fn;

    handle = dlopen("libpoem.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        exit(EXIT_FAILURE);
    }

    dlerror();    /* Clear any existing error */

    long int function_address [ndat_size] ;
    // Do change position
    for(int i = 0;  i < ndat_size ; i++){
        char* full_func_name;
        char function_name[] ="code_";
        char num [100] ;
        sprintf(num, "%d", i);
        full_func_name = strcat(function_name , num);
        fn=dlsym(handle, full_func_name);
        function_address[i] = (long int)fn;
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "%s\n", error);
            exit(EXIT_FAILURE);
        }
    }
    dlclose(handle);

    // find max page size to do mprotect
    int max_offset = INT_MIN;
    int min_offset = INT_MAX;
    for(int i = 0 ; i < GOT_Table_size ; i++){
        if(table[i].got_offset > max_offset) max_offset = table[i].got_offset ;
        if(table[i].got_offset < min_offset) min_offset = table[i].got_offset ;
    }
    // printf("%x\n",max_offset);
    // printf("%x\n",min_offset);

    long int max_page = basic_address + min_offset;
    printf("The min page protect address should be: %lx\n",max_page);
    if (mprotect(main_min , main_max-main_min , PROT_WRITE)) {
        perror("Couldn’t mprotect");
        exit(errno);
    }

    //change function address in GOT entry
    for(int i = 0;  i < GOT_Table_size ; i++){
        long int got_address = basic_address + table[i].got_offset;
        long int* got_pointer = got_address;
        for(int j = 0 ; j < ndat_size ; j++){
            // printf("index is %d\n",j);
            if(table[i].code_num == ndat[j]){
                *got_pointer =  function_address[j];

            }
        }
    }
}
