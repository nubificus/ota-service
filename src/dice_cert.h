#pragma once

#ifdef OTA_SECURE

#ifndef __OTA_DICE_CERT_H__
#define __OTA_DICE_CERT_H__ 

int gen_dice_cert(void *buf, size_t max_len);

/* Uses the cache */
int get_dice_cert_ptr(unsigned char **ptr);

#endif

#endif
