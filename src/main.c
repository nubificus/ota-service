#include <stdio.h>
#include <stdint.h>
#include <dice/dice.h>

int main(int argc, char** argv) {
  (void)argc;
  (void)argv;
  uint8_t cdi_buffer[DICE_CDI_SIZE] = {0};
  uint8_t cert_buffer[2048];
  DiceResult ret;
  size_t cert_size;
  DiceInputValues input_values = {0};
  int i;

  ret = DiceMainFlow(/*context=*/NULL, cdi_buffer, cdi_buffer,
                           &input_values, sizeof(cert_buffer), cert_buffer,
                           &cert_size, cdi_buffer, cdi_buffer);
  for (i = 0; i < DICE_CDI_SIZE; i++) {
	  printf("%c", cdi_buffer[i]);
  }

  return (int)(ret);
}
