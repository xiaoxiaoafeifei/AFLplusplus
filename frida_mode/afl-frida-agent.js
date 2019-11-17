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

var MAP_SIZE = 65536;

var STALKER_QUEUE_CAP = 100000000;
var STALKER_QUEUE_DRAIN_INT = 1000*1000;

var afl_area_ptr = undefined;
var target_function = undefined;
var func_handle = undefined;

var payload_memory = undefined;
var payload_max_len = 0;
var input_filename = undefined;

// Stalker tuning
Stalker.trustThreshold = 0;
Stalker.queueCapacity = STALKER_QUEUE_CAP;
Stalker.queueDrainInterval = STALKER_QUEUE_DRAIN_INT;
console.log(" >> asdasd-frida-agent loaded!");
/*
var maps = function() {

    var maps = Process.enumerateModulesSync();
    var i = 0;
    
    maps.map(function(o) { o.id = i++; });
    maps.map(function(o) { o.end = o.base.add(o.size); });

    return maps;

}();*/

var shmat_addr = Module.findExportByName(null, "shmat");
var shmat = new NativeFunction(shmat_addr, 'pointer', ['int', 'pointer', 'int']);

var open_addr = Module.findExportByName(null, "open");
var open = new NativeFunction(open_addr, 'int', ['pointer', 'int', 'int']);

var read_addr = Module.findExportByName(null, "read");
var read = new NativeFunction(read_addr, 'int', ['int', 'pointer', 'int']);

var close_addr = Module.findExportByName(null, "close");
var close = new NativeFunction(close_addr, 'void', ['int']);


rpc.exports = {

    setup: function(shm_id, filename_hex, target, max_len) {
    
        console.log("Setup")
        
        afl_area_ptr = shmat(shm_id, ptr(0), 0);
        
        target_function = ptr(target);

        input_filename = Memory.alloc(filename_hex.length / 2);
        
        var filename = [];
        for(var i = 0; i < filename_hex.length; i+=2)
            filename.push(parseInt(filename_hex.substring(i, i + 2), 16));

        filename = new Uint8Array(filename)
        Memory.writeByteArray(input_filename, filename)
        
        payload_max_len = max_len;
        payload_memory = Memory.alloc(max_len);
        
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

        var fd = open(input_filename, 0, 0);
        var len = read(fd, payload_memory, payload_max_len);
        close(fd);
        
        if (len < 0) return false;
        
        var retval = func_handle(payload_memory, len);
    },
};

console.log(" >> afl-frida-agent loaded!");

