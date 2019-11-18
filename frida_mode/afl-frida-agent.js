/*

   american fuzzy lop++ - frida agent instrumentation
   --------------------------------------------------

   Written and maintained by Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2019 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

'use strict'

// TO USER: change this
var PAYLOAD_MAX_LEN = 4096;
var TARGET_MODULE = "test";
var TARGET_FUNCTION = ptr("0x0000068a"); // target_func from nm

var MAP_SIZE = 65536; // default value in AFL++

var STALKER_QUEUE_CAP = 100000000;
var STALKER_QUEUE_DRAIN_INT = 1000*1000;

var afl_area_ptr = undefined;
var target_function = undefined;
var func_handle = undefined;

var payload_memory = undefined;
var input_filename = undefined;

// Stalker tuning
Stalker.trustThreshold = 0;
Stalker.queueCapacity = STALKER_QUEUE_CAP;
Stalker.queueDrainInterval = STALKER_QUEUE_DRAIN_INT;


var maps = function() {

    var maps = Process.enumerateModulesSync();
    var i = 0;
    
    maps.map(function(o) { o.id = i++; });
    maps.map(function(o) { o.end = o.base.add(o.size); });

    return maps;

}();

var shmat_addr = Module.findExportByName(null, "shmat");
var shmat = undefined;
if (shmat_addr === null) {
  // No shmat, Android?
  var cm = new CModule(" \n\
  #include <fcntl.h> \n\
  #include <linux/shm.h> \n\
  #include <linux/ashmem.h> \n\
  #include <sys/ioctl.h> \n\
  #include <sys/mman.h> \n\
   \n\
  void *android_shmat(int __shmid, const void *__shmaddr, int __shmflg) { \n\
    (void) __shmflg; \n\
    int   size; \n\
    void *ptr; \n\
     \n\
    size = ioctl(__shmid, ASHMEM_GET_SIZE, NULL); \n\
    if (size < 0) { return NULL; } \n\
     \n\
    ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, __shmid, 0); \n\
    if (ptr == MAP_FAILED) { return NULL; } \n\
     \n\
    return ptr; \n\
     \n\
  } \n\
  ");
  shmat = cm.android_shmat;
} else {
  shmat = new NativeFunction(shmat_addr, 'pointer', ['int', 'pointer', 'int']);
}

var open_addr = Module.getExportByName(null, "open");
var open = new NativeFunction(open_addr, 'int', ['pointer', 'int', 'int']);

var read_addr = Module.getExportByName(null, "read");
var read = new NativeFunction(read_addr, 'int', ['int', 'pointer', 'int']);

var close_addr = Module.getExportByName(null, "close");
var close = new NativeFunction(close_addr, 'void', ['int']);


rpc.exports = {

    setup: function(shm_id, filename_hex, map_size) {
         
        MAP_SIZE = map_size;
        
        afl_area_ptr = shmat(shm_id, ptr(0), 0);
        
        target_function = Module.findBaseAddress(TARGET_MODULE);
        target_function = target_function.add(TARGET_FUNCTION);
        console.log(target_function)
        input_filename = Memory.alloc(filename_hex.length / 2 +1);
        
        var filename = [];
        for(var i = 0; i < filename_hex.length; i+=2)
            filename.push(parseInt(filename_hex.substring(i, i + 2), 16));
        
        filename = new Uint8Array(filename) 
        Memory.writeByteArray(input_filename, filename);
        input_filename.add(filename_hex.length / 2).writeU8(0);

        payload_memory = Memory.alloc(PAYLOAD_MAX_LEN);
        
        // TO USER: Customize parameters for your use case
        func_handle = new NativeFunction(target_function, 'void', ['pointer', 'int']);
        
        var prev_loc_ptr = Memory.alloc(32);
        var prev_loc = 0;
        
        function afl_maybe_log (context) {
          
          var cur_loc = context.pc.toInt32();
          
          cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
          cur_loc &= MAP_SIZE - 1;

          //afl_area[cur_loc ^ prev_loc]++;
          var x = afl_area_ptr.add(cur_loc ^ prev_loc);
          x.writeU8((x.readU8() +1) & 0xff);

          prev_loc = cur_loc >> 1;

        }
        
        var generic_transform = function (iterator) {
        
          var i = iterator.next();
          
          iterator.putCallout(afl_maybe_log);

          do iterator.keep()
          while ((i = iterator.next()) !== null);

        }
        
        var transforms = {
          "x64": function (iterator) {
          
            var i = iterator.next();
            
            var cur_loc = i.address;
            cur_loc = cur_loc.shr(4).xor(cur_loc.shl(8));
            cur_loc = cur_loc.and(MAP_SIZE - 1);
            
            iterator.putPushfx();
            iterator.putPushReg("rdx");
            iterator.putPushReg("rcx");
            iterator.putPushReg("rbx");

            // rdx = cur_loc
            iterator.putMovRegAddress("rdx", cur_loc);
            // rbx = &prev_loc
            iterator.putMovRegAddress("rbx", prev_loc_ptr);
            // rcx = *rbx
            iterator.putMovRegRegPtr("rcx", "rbx");
            // rcx ^= rdx
            iterator.putXorRegReg("rcx", "rdx");
            // rdx = cur_loc >> 1
            iterator.putMovRegAddress("rdx", cur_loc.shr(1));
            // *rbx = rdx
            iterator.putMovRegPtrReg("rbx", "rdx");
            // rbx = afl_area_ptr
            iterator.putMovRegAddress("rbx", afl_area_ptr);
            // rbx += rcx
            iterator.putAddRegReg("rbx", "rcx");
            // (*rbx)++
            iterator.putU8(0xfe); // inc byte ptr [rbx]
            iterator.putU8(0x03);
         
            iterator.putPopReg("rbx");
            iterator.putPopReg("rcx");
            iterator.putPopReg("rdx");
            iterator.putPopfx();

            do iterator.keep()
            while ((i = iterator.next()) !== null);

          },
          // TODO inline ARM code
          "ia32": generic_transform,
          "arm": generic_transform,
          "arm64": generic_transform
        };
        
        Stalker.follow(Process.getCurrentThreadId(), {
            events: {
                call: false,
                ret: false,
                exec: false,
                block: false,
                compile: true
            },
            
          transform: transforms[Process.arch],
        });
    },

    execute: function () {
        if(target_function == undefined)
            return false;
        
        console.log(input_filename.readCString())
        var fd = open(input_filename, 0, 0);
        var len = read(fd, payload_memory, PAYLOAD_MAX_LEN);
        close(fd);
        
        if (len < 0) return false;
        
        // TO USER: Adapt this harness call
        var retval = func_handle(payload_memory, len);
    },
};

console.log(" >> afl-frida-agent loaded!");

