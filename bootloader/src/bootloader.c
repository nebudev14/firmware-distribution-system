// Hardware Imports
#include "inc/hw_memmap.h" // Peripheral Base Addresses
#include "inc/lm3s6965.h"  // Peripheral Bit Masks and Registers
#include "inc/hw_types.h"  // Boolean type
#include "inc/hw_ints.h"   // Interrupt numbers

// Driver API Imports
#include "driverlib/flash.h"     // FLASH API
#include "driverlib/sysctl.h"    // System control API (clock/reset)
#include "driverlib/interrupt.h" // Interrupt API
#include "beaverssl.h"
#include "bearssl.h"

// Library Imports
#include <string.h>

// Application Imports
#include "uart.h"

// Forward Declarations
void load_initial_firmware(void);
void load_firmware(void);
void boot_firmware(void);
long program_flash(uint32_t, unsigned char *, unsigned int);
void read_frame(uint8_t uart_num, uint8_t *data);
void reject();

// Firmware Constants
#define METADATA_BASE 0xFC00 // base address of version and firmware size in Flash
#define FW_BASE 0x10000      // base address of firmware in Flash
#define FW_MEM_BASE 0x100000 // base address of firmware in RAM

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Protocol Constants
#define OK ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)
#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')

// Size constants
#define MAX_FIRMWARE_SIZE 32768 // max firmware size of 32768 bytes
#define AES_KEY_LENGTH 16
#define V_KEY_LENGTH 64
#define ECC_KEY_LENGTH 44

// Keys
char AES_KEY[AES_KEY_LENGTH] = AES;
char V_KEY[V_KEY_LENGTH] = VIG;
char ECC_KEY[ECC_KEY_LENGTH] = ECC;

// Firmware v2 is embedded in bootloader
// Read up on these symbols in the objcopy man page (if you want)!
extern int _binary_firmware_bin_start;
extern int _binary_firmware_bin_size;

// Device metadata
uint16_t *fw_version_address = (uint16_t *)METADATA_BASE;
uint16_t *fw_size_address = (uint16_t *)(METADATA_BASE + 2);
uint8_t *fw_release_message_address;

// Firmware Buffer
unsigned char data[FLASH_PAGESIZE];

int main(void)
{

  // A 'reset' on UART0 will re-start this code at the top of main, won't clear flash, but will clean ram.

  // Initialize UART channels
  // 0: Reset
  // 1: Host Connection
  // 2: Debug
  uart_init(UART0);
  uart_init(UART1);
  uart_init(UART2);

  // Enable UART0 interrupt
  IntEnable(INT_UART0);
  IntMasterEnable();

  load_initial_firmware(); // note the short-circuit behavior in this function, it doesn't finish running on reset!

  uart_write_str(UART2, "Welcome to the BWSI Vehicle Update Service!\n");
  uart_write_str(UART2, "Send \"U\" to update, and \"B\" to run the firmware.\n");
  uart_write_str(UART2, "Writing 0x20 to UART0 will reset the device.\n");

  int resp;
  while (1)
  {
    uint32_t instruction = uart_read(UART1, BLOCKING, &resp);
    if (instruction == UPDATE)
    {
      uart_write_str(UART1, "U");
      load_firmware();
    }
    else if (instruction == BOOT)
    {
      uart_write_str(UART1, "B");
      boot_firmware();
    }
  }
}

/*
 * Load initial firmware into flash
 */
void load_initial_firmware(void)
{

  if (*((uint32_t *)(METADATA_BASE)) != 0xFFFFFFFF)
  {
    /*
     * Default Flash startup state is all FF since. Only load initial
     * firmware when metadata page is all FF. Thus, exit if there has
     * been a reset!
     */
    return;
  }

  // Create buffers for saving the release message
  uint8_t temp_buf[FLASH_PAGESIZE];
  char initial_msg[] = "This is the initial release message.";
  uint16_t msg_len = strlen(initial_msg) + 1;
  uint16_t rem_msg_bytes;

  // Get included initial firmware
  int size = (int)&_binary_firmware_bin_size;
  uint8_t *initial_data = (uint8_t *)&_binary_firmware_bin_start;

  // Set version 2 and install
  uint16_t version = 2;
  uint32_t metadata = (((uint16_t)size & 0xFFFF) << 16) | (version & 0xFFFF);
  program_flash(METADATA_BASE, (uint8_t *)(&metadata), 4);

  int i;

  for (i = 0; i < size / FLASH_PAGESIZE; i++)
  {
    program_flash(FW_BASE + (i * FLASH_PAGESIZE), initial_data + (i * FLASH_PAGESIZE), FLASH_PAGESIZE);
  }

  /* At end of firmware. Since the last page may be incomplete, we copy the initial
   * release message into the unused space in the last page. If the firmware fully
   * uses the last page, the release message simply is written to a new page.
   */

  uint16_t rem_fw_bytes = size % FLASH_PAGESIZE;
  if (rem_fw_bytes == 0)
  {
    // No firmware left. Just write the release message
    program_flash(FW_BASE + (i * FLASH_PAGESIZE), (uint8_t *)initial_msg, msg_len);
  }
  else
  {
    // Some firmware left. Determine how many bytes of release message can fit
    if (msg_len > (FLASH_PAGESIZE - rem_fw_bytes))
    {
      rem_msg_bytes = msg_len - (FLASH_PAGESIZE - rem_fw_bytes);
    }
    else
    {
      rem_msg_bytes = 0;
    }

    // Copy rest of firmware
    memcpy(temp_buf, initial_data + (i * FLASH_PAGESIZE), rem_fw_bytes);
    // Copy what will fit of the release message
    memcpy(temp_buf + rem_fw_bytes, initial_msg, msg_len - rem_msg_bytes);
    // Program the final firmware and first part of the release message
    program_flash(FW_BASE + (i * FLASH_PAGESIZE), temp_buf, rem_fw_bytes + (msg_len - rem_msg_bytes));

    if (rem_msg_bytes > 0)
    {
      // If there are more bytes, program them directly from the release message string
      // Writing to a new page. Increment pointer
      i++;
      program_flash(FW_BASE + (i * FLASH_PAGESIZE), (uint8_t *)(initial_msg + (msg_len - rem_msg_bytes)), rem_msg_bytes);
    }
  }
}

// read a 64 byte frame of data from specified UART interface
void read_frame(uint8_t uart_num, uint8_t *data)
{
  uint32_t instruction;
  int resp;
  uint8_t i;
  for (i = 0; i < 64; i++)
  {
    instruction = uart_read(uart_num, BLOCKING, &resp);
    *(data + i) = instruction;
  }
}

void reject()
{
  uart_write(UART1, ERROR); // tell client there is error
  SysCtlReset();            // Reset device
}
/*
 * Load the firmware into flash.
 */
void load_firmware(void)
{
  int frame_length = 0;
  int read = 0;
  uint32_t rcv = 0;

  uint32_t data_index = 0;
  uint32_t page_addr = FW_BASE;
  uint32_t version = 0;

  // 16 byte authentication tag
  uint8_t auth_tag[16];
  for (int i = 0; i < 16; i++)
  {
    auth_tag[i] = uart_read(UART1, BLOCKING, &read);
  }
  // 12 byte nonce
  uint8_t nonce[12];
  for (int i = 0; i < 12; i++)
  {
    nonce[i] = uart_read(UART1, BLOCKING, &read);
  }
  // empty read for the next 64 - (12 + 16) bytes of data
  for (int i = 0; i < 64 - (12 + 16); i++)
  {
    uint8_t temp = uart_read(UART1, BLOCKING, &read);
    // if temp is not null byte
    if (temp != 0)
    {
      reject();
      return;
    }
  }

  // Compare to old version and abort if older (note special case for version 0).
  uint16_t old_version = *fw_version_address;

  if (version != 0 && version < old_version)
  {
    reject();
    return;
  }
  else if (version == 0)
  {
    // If debug firmware, don't change version
    version = old_version;
  }

  // Write new firmware size and version to Flash
  // size (temp pls change)
  uint16_t size = 69;
  // Create 32 bit word for flash programming, version is at lower address, size is at higher address
  uint32_t metadata = ((size & 0xFFFF) << 16) | (version & 0xFFFF);
  program_flash(METADATA_BASE, (uint8_t *)(&metadata), 4);

  uart_write(UART1, OK); // Acknowledge the metadata.

  uint8_t * sp = FW_MEM_BASE;
  int all_data_index = 0;
  uint8_t frame_counter = 0;
  // loops until data array becomes 64 null bytes
  while (all_data_index < MAX_FIRMWARE_SIZE)
  {
    // read 64 bytes of data from UART1
    read_frame(UART1, sp+frame_counter*64);
      
    
    // if data is all null bytes, break loop
    // sorry
    if (data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 0 && data[4] == 0 && data[5] == 0 && data[6] == 0 && data[7] == 0 && data[8] == 0 && data[9] == 0 && data[10] == 0 && data[11] == 0 && data[12] == 0 && data[13] == 0 && data[14] == 0 && data[15] == 0 && data[16] == 0 && data[17] == 0 && data[18] == 0 && data[19] == 0 && data[20] == 0 && data[21] == 0 && data[22] == 0 && data[23] == 0 && data[24] == 0 && data[25] == 0 && data[26] == 0 && data[27] == 0 && data[28] == 0 && data[29] == 0 && data[30] == 0 && data[31] == 0 && data[32] == 0 && data[33] == 0 && data[34] == 0 && data[35] == 0 && data[36] == 0 && data[37] == 0 && data[38] == 0 && data[39] == 0 && data[40] == 0 && data[41] == 0 && data[42] == 0 && data[43] == 0 && data[44] == 0 && data[45] == 0 && data[46] == 0 && data[47] == 0 && data[48] == 0 && data[49] == 0 && data[50] == 0 && data[51] == 0 && data[52] == 0 && data[53] == 0 && data[54] == 0 && data[55] == 0 && data[56] == 0 && data[57] == 0 && data[58] == 0 && data[59] == 0 && data[60] == 0 && data[61] == 0 && data[62] == 0 && data[63] == 0)
    {
      break;
    }
    frame_counter += 1; // this is put afterwards so last frame isn't counted as a data frame even though null frame is written
  }

  // Decrypt and verify
  
  // Vignere decryption
  for (int i=0; i<64*frame_counter; i++){
    *(sp + i) = V_KEY[i%64] ^ *(sp + i);
  }
  //not a while loop for accidental nulls
  
  char auth_tag[16];
  char nonce[12];
  char ecc_sign[64];
  
  &auth_tag[0] = FW_MEM_BASE;
  &nonce[0] = FW_MEM_BASE+16;
  &ecc_char[0] = FW_MEM_BASE+64; //remember the padding
  
  char aad[0]; // Empty char array bc we're not using AAD
  
  // GCM decrypt
  if (gcm_decrypt_and_verify(AES_KEY, nonce, FW_MEM_BASE+64, (frame_counter-1)*64, aad, 0, auth_tag) != 1) //this prolly won't work
    //first frame is tag and nonce so should be excluded
  {
    reject();
    return;
  }

  // Grab all data excluding ECC signature
  char data_no_signature[(frame_counter-2)*64];
  &data_no_signature = FW_MEM_BASE+64*2

  // Hash data
  unsigned char hashed_data[32];
  sha_hash(data_no_signature, all_data_index - 64, hashed_data); //not sure which part is actually hashed

  // Verify ECC signature
  if (br_ecdsa_i31_vrfy_asn1(br_ec_p256_m31, hashed_data, 32, ECC_KEY, ecc_signature, 64) != 1)
  {
    reject();
    return;
  }

  /* Loop here until you can get all your characters and stuff */
  while (1)
  {

    // Get two bytes for the length.
    rcv = uart_read(UART1, BLOCKING, &read);
    frame_length = (int)rcv << 8;
    rcv = uart_read(UART1, BLOCKING, &read);
    frame_length += (int)rcv;

    // Write length debug message
    uart_write_hex(UART2, frame_length);
    nl(UART2);

    // Get the number of bytes specified
    for (int i = 0; i < frame_length; ++i)
    {
      data[data_index] = uart_read(UART1, BLOCKING, &read);
      data_index += 1;
    } // for

    // If we filed our page buffer, program it
    if (data_index == FLASH_PAGESIZE || frame_length == 0)
    {
      // Try to write flash and check for error
      if (program_flash(page_addr, data, data_index))
      {
        reject();
        return;
      }
#if 1
      // Write debugging messages to UART2.
      uart_write_str(UART2, "Page successfully programmed\nAddress: ");
      uart_write_hex(UART2, page_addr);
      uart_write_str(UART2, "\nBytes: ");
      uart_write_hex(UART2, data_index);
      nl(UART2);
#endif

      // Update to next page
      page_addr += FLASH_PAGESIZE;
      data_index = 0;

      // If at end of firmware, go to main
      if (frame_length == 0)
      {
        uart_write(UART1, OK);
        break;
      }
    } // if

    uart_write(UART1, OK); // Acknowledge the frame.
  }                        // while(1)
}

/*
 * Program a stream of bytes to the flash.
 * This function takes the starting address of a 1KB page, a pointer to the
 * data to write, and the number of byets to write.
 *
 * This functions performs an erase of the specified flash page before writing
 * the data.
 */
long program_flash(uint32_t page_addr, unsigned char *data, unsigned int data_len)
{
  uint32_t word = 0;
  int ret;
  int i;

  // Erase next FLASH page
  FlashErase(page_addr);

  // Clear potentially unused bytes in last word
  // If data not a multiple of 4 (word size), program up to the last word
  // Then create temporary variable to create a full last word
  if (data_len % FLASH_WRITESIZE)
  {
    // Get number of unused bytes
    int rem = data_len % FLASH_WRITESIZE;
    int num_full_bytes = data_len - rem;

    // Program up to the last word
    ret = FlashProgram((unsigned long *)data, page_addr, num_full_bytes);
    if (ret != 0)
    {
      return ret;
    }

    // Create last word variable -- fill unused with 0xFF
    for (i = 0; i < rem; i++)
    {
      word = (word >> 8) | (data[num_full_bytes + i] << 24); // Essentially a shift register from MSB->LSB
    }
    for (i = i; i < 4; i++)
    {
      word = (word >> 8) | 0xFF000000;
    }

    // Program word
    return FlashProgram(&word, page_addr + num_full_bytes, 4);
  }
  else
  {
    // Write full buffer of 4-byte words
    return FlashProgram((unsigned long *)data, page_addr, data_len);
  }
}

void boot_firmware(void)
{
  // compute the release message address, and then print it
  uint16_t fw_size = *fw_size_address;
  fw_release_message_address = (uint8_t *)(FW_BASE + fw_size);
  uart_write_str(UART2, (char *)fw_release_message_address);

  // Boot the firmware
  __asm(
      "LDR R0,=0x10001\n\t"
      "BX R0\n\t");
}
