#ifndef __NTGRCRYPT_H__
#define __NTGRCRYPT_H__

#define NTGRCRYPT_SUCCESS 0
#define NTGRCRYPT_FAILURE -1

extern int ntgrcrypt_init(void);
extern int ntgrcrypt_open(void);
extern int ntgrcrypt_close(void);
extern int ntgrcrypt_reset(void);
extern int ntgrcrypt_renew(void);
#endif
