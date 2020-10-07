#include <unbound.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#define UB_OPTION(k, v) assert(ub_ctx_set_option(ctx, k, v) == 0)

#define RRTYPE_CAA 257
#define RRCLASS_INET 1

int main(int argc, char **argv)
{
  struct ub_ctx *ctx = ub_ctx_create();
  struct ub_result *result = calloc(sizeof(struct ub_result), 1);

  UB_OPTION("verbosity:", "9");
  UB_OPTION("use-syslog:", "no");
  UB_OPTION("do-ip4:", "yes");
  UB_OPTION("do-ip6:", "yes");
  UB_OPTION("do-udp:", "yes");
  UB_OPTION("do-tcp:", "yes");
  UB_OPTION("tcp-upstream:", "no");
  UB_OPTION("harden-glue:", "yes");
  UB_OPTION("harden-dnssec-stripped:", "yes");
  UB_OPTION("cache-min-ttl:", "0");
  UB_OPTION("cache-max-ttl:", "0");
  UB_OPTION("cache-max-negative-ttl:", "0");
  UB_OPTION("neg-cache-size:", "0");
  UB_OPTION("prefetch:", "no");
  UB_OPTION("unwanted-reply-threshold:", "10000");
  UB_OPTION("do-not-query-localhost:", "yes");
  UB_OPTION("val-clean-additional:", "yes");
  UB_OPTION("harden-algo-downgrade:", "yes");
  UB_OPTION("edns-buffer-size:", "512");
  UB_OPTION("val-sig-skew-min:", "0");
  UB_OPTION("val-sig-skew-max:", "0");
  UB_OPTION("use-caps-for-id:", "yes");

  assert(ub_ctx_add_ta(ctx, ".       172800  IN      DNSKEY  257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=\
.       172800  IN      DNSKEY  256 3 8 AwEAAdp440E6Mz7c+Vl4sPd0lTv2Qnc85dTW64j0RDD7sS/zwxWDJ3QRES2VKDO0OXLMqVJSs2YCCSDKuZXpDPuf++YfAu0j7lzYYdWTGwyNZhEaXtMQJIKYB96pW6cRkiG2Dn8S2vvo/PxW9PKQsyLbtd8PcwWglHgReBVp7kEv/Dd+3b3YMukt4jnWgDUddAySg558Zld+c9eGWkgWoOiuhg4rQRkFstMX1pRyOSHcZuH38o1WcsT4y3eT0U/SR6TOSLIB/8Ftirux/h297oS7tCcwSPt0wwry5OFNTlfMo8v7WGurogfk8hPipf7TTKHIi20LWen5RCsvYsQBkYGpF78=\
.       172800  IN      DNSKEY  257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=\
.       172800  IN      RRSIG   DNSKEY 8 0 172800 20181101000000 20181011000000 20326 . M/LTswhCjuJUTvX1CFqC+TiJ4Fez7AROa5mM+1AI2MJ+zLHhr3JaMxyydFLWrBHR0056Hz7hNqQ9i63hGeiR6uMfanF0jIRb9XqgGP8nY37T8ESpS1UiM9rJn4b40RFqDSEvuFdd4hGwK3EX0snOCLdUT8JezxtreXI0RilmqDC2g44TAKyFw+Is9Qwl+k6+fbMQ/atA8adANbYgyuHfiwQCCUtXRaTCpRgQtsAz9izO0VYIGeHIoJta0demAIrLCOHNVH2ogHTqMEQ18VqUNzTd0aGURACBdS7PeP2KogPD7N8Q970O84TFmO4ahPIvqO+milCn5OQTbbgsjHqY6Q==") == 0);

  if (ub_resolve(ctx, "shop.agit-global.com", RRTYPE_CAA, RRCLASS_INET, &result) != 0)
  {
    fprintf(stderr, "Query failed\n");
    exit(1);
  }

  fprintf(stdout, "rrcode: %d, secure=%d\n", result->rcode, result->secure);

  free(result);
  ub_ctx_delete(ctx);

  return 0;
}