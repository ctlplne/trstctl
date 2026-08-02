(module
  ;; trstctl plugin capability ABI. Every argument is an offset or a length into
  ;; this module's own exported memory; the result is a status code:
  ;;   0 = ok, 1 = denied by the capability grant, 2 = error.
  ;;
  ;; The host exports cap_write ONLY when the deployment grants fs.write. If it
  ;; does not, this import cannot resolve and the module fails to instantiate --
  ;; that is the sandbox closing the plugin's reach before it runs, not a bug.
  (import "env" "cap_write"
    (func $cap_write (param i32 i32 i32 i32) (result i32)))

  ;; The host reads the path and payload out of this memory, so it must be
  ;; exported under the name "memory".
  (memory (export "memory") 1)
  (data (i32.const 0) "/var/lib/trstctl/plugins/out/deployed.txtdeployed")

  ;; run() is the conformance entry point. It performs no privileged call, so this
  ;; module also passes conformance at zero capabilities.
  (func (export "run") (result i32)
    i32.const 0)

  ;; deploy() writes the payload. The write only succeeds if the grant covers the
  ;; path above; the sandbox performs it through a directory handle opened at the
  ;; granted prefix, so a symlink pointing out of that prefix is refused.
  (func (export "deploy") (result i32)
    i32.const 0    ;; path_ptr
    i32.const 41   ;; path_len
    i32.const 41   ;; data_ptr
    i32.const 8    ;; data_len
    call $cap_write))
