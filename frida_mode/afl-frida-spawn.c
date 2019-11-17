/*
 * Compile with:
 *
 * /usr/bin/gcc -static-libgcc -fPIC -m64 -ffunction-sections -fdata-sections -Wall -Os -pipe -g3 frida-core-example.c -o frida-core-example -L. -lfrida-core -ldl -lm -ldl -lm -ldl -lrt -ldl -lrt -ldl -ldl -lresolv -ldl -lrt -lm -Wl,--export-dynamic -Wl,--gc-sections,-z,noexecstack -L/worker/frida-linux-x86/build/build/frida-linux-x86_64/lib -L/worker/frida-linux-x86/build/build/sdk-linux-x86_64/lib
 *
 *gcc -static-libgcc -fPIC -m64 -ffunction-sections -fdata-sections -Wall -Os -pipe -g3 afl-frida-spawn.c -o afl-frida-spawn -L. -lfrida-core -ldl -lm -ldl -lm -ldl -lrt -ldl -lrt -ldl -ldl -lresolv -ldl -lrt -lm -Wl,--export-dynamic -Wl,--gc-sections,-z,noexecstack -pthread
 * Visit www.frida.re to learn more about Frida.
 */

#include "frida-core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// TO USER: Change this
#define PAYLOAD_MAX_LEN 4096
#define TARGET_FUNCTION 0x0000000000401156

#define SHM_ENV_VAR "__AFL_SHM_ID"
#define FORKSRV_FD 198

static size_t req_id;
static char msg_buf[200];

static guint target_pid;

static FridaSession * session;
static FridaScript * script;
static FridaDeviceManager * manager;
static FridaDevice * local_device;

static GError * error = NULL;

static void clean_exit(int status) {

  g_print(" >> Clean exit %d\n", status);

  if (script) {
    frida_script_unload_sync (script, NULL, NULL);
    frida_unref (script);
    g_print ("[*] Unloaded\n");
  }

  if (session) {
    frida_session_detach_sync (session, NULL, NULL);
    frida_unref (session);
    g_print ("[*] Detached\n");
  }
  
  if (local_device)
    frida_unref (local_device);

  if (manager) {
    frida_device_manager_close_sync (manager, NULL, NULL);
    frida_unref (manager);
    g_print ("[*] Closed\n");
  }
  
  exit(status);
  
}


char *read_file(char *path, size_t *length) {

  size_t len;
  char * buf;

  FILE *fp = fopen(path, "rb");
  if (fp == NULL) return NULL;
  
  fseek(fp, 0, SEEK_END);
  len = ftell(fp);
  buf = malloc(len);
  rewind(fp);
  fread(buf, 1, len, fp);
  fclose(fp);
  *length = len;

  return buf;

}

// from https://stackoverflow.com/questions/6357031/how-do-you-convert-a-byte-array-to-a-hexadecimal-string-in-c
void tohex(unsigned char * in, size_t insz, char * out)
{
    unsigned char * pin = in;
    const char * hex = "0123456789ABCDEF";
    char * pout = out;
    for(; pin < in+insz; pout +=2, pin++){
        pout[0] = hex[(*pin>>4) & 0xF];
        pout[1] = hex[ *pin     & 0xF];
    }
    pout[0] = 0;
}

static void mimic_forkserver() {

  static unsigned char tmp[4];
  pid_t                child_pid;
  int fake_status = 0;

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) {
    g_print(" >> No forkserver, no party\n");
    return;
  }

  while (1) {

    int status;
    unsigned int was_killed;
    // wait for afl-fuzz
    if (read(FORKSRV_FD, &was_killed, 4) != 4) clean_exit(2);

    // write child pid to afl-fuzz
    if (write(FORKSRV_FD + 1, &target_pid, 4) != 4) clean_exit(5);
    
    sprintf(msg_buf, "[\"frida:rpc\", %lu, \"call\", \"execute\", []]", ++req_id);
    
    frida_script_post_sync(script, msg_buf, NULL, NULL, &error);
    
    if (error != NULL) {
      fake_status = 134; // abort
    }

    // send child stop status to afl-fuzz
    if (write(FORKSRV_FD + 1, &fake_status, 4) != 4) clean_exit(7);
    
    fake_status = 0;

  }

}


int
main (int argc, char * argv[])
{
  FridaDeviceList * devices;
  gint num_devices, i;

  int shm_id;
  char *id_str = getenv(SHM_ENV_VAR);
  if (!id_str) {
    g_printerr (SHM_ENV_VAR " not defined!\n", argv[0]);
    return 1;
  }

  shm_id = atoi(id_str);

  frida_init ();

  if (argc < 3)
  {
    g_printerr ("Usage: %s <input filename> <target program> [target args...]\n", argv[0]);
    return 1;
  }

  manager = frida_device_manager_new ();

  devices = frida_device_manager_enumerate_devices_sync (manager, NULL, &error);
  g_assert (error == NULL);

  local_device = NULL;
  num_devices = frida_device_list_size (devices);
  for (i = 0; i != num_devices; i++)
  {
    FridaDevice * device = frida_device_list_get (devices, i);

    g_print ("[*] Found device: \"%s\"\n", frida_device_get_name (device));

    if (frida_device_get_dtype (device) == FRIDA_DEVICE_TYPE_LOCAL)
      local_device = g_object_ref (device);

    g_object_unref (device);
  }
  g_assert (local_device != NULL);

  frida_unref (devices);
  devices = NULL;
  
  size_t agent_code_len;
  char * agent_code = read_file("afl-frida-agent.js", &agent_code_len);
  
  if (!agent_code) {
    g_printerr ("Failed to open afl-frida-agent.js\n");
    return 1;
  }
  
  g_print (" >> Try to spawn %s on %s\n", argv[2], frida_device_get_name (local_device));
  
  FridaSpawnOptions *options = frida_spawn_options_new ();
	const int tgt_argc = argc -2;
	if (tgt_argc > 1)
		frida_spawn_options_set_argv (options, argv +2, tgt_argc);
	target_pid = frida_device_spawn_sync (local_device, argv[2], options, NULL, &error);
	g_object_unref (options);
  
  if (error == NULL)
  {
    FridaScriptOptions * options;

    g_print ("[*] Spawned with pid %d\n", target_pid);

    options = frida_script_options_new ();
    frida_script_options_set_name (options, "afl-frida-agent");
    frida_script_options_set_runtime (options, FRIDA_SCRIPT_RUNTIME_V8);
    
    script = frida_session_create_script_sync (session, agent_code, options,
                                               NULL, &error);
    g_assert (error == NULL);

    g_clear_object (&options);
    
    g_print ("[*] Script created\n");

    frida_script_load_sync (script, NULL, &error);
    g_assert (error == NULL);

    g_print ("[*] Script loaded\n");
    
    size_t in_file_len = strlen(argv[1]);
    char * in_file_hex = malloc(in_file_len * 2 + 1);
    
    tohex(argv[1], in_file_len, in_file_hex);
    
    sprintf(msg_buf,
            "[\"frida:rpc\", %lu, \"call\", \"setup\", [%d, \"%s\", %llu, %lu]]",
             ++req_id, shm_id, in_file_hex, TARGET_FUNCTION, PAYLOAD_MAX_LEN);

    frida_script_post_sync(script, msg_buf, NULL, NULL, &error);
    if (error != NULL) clean_exit(1);
    
    g_print(" >> Starting fake forkserver\n");
    
    mimic_forkserver();

  }
  else
  {
    g_printerr ("Failed to attach: %s\n", error->message);
    g_error_free (error);
  }
  
  g_print ("[*] Exiting\n");

  clean_exit(0);
}


