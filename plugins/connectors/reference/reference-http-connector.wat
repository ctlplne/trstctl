;; trstctl reference connector: deploy over an appliance's HTTP API.
;;
;; The relay makes this module's HTTP requests itself. It adds the target's
;; credential ("auth": "basic" uses the target's username and the redeemed
;; password_ref; "bearer" and "header" use token_ref), splices the certificate
;; and private key into the JSON body where a value is {"$input": "<name>"},
;; and removes every redeemed value from the response before this module reads
;; it. The module never holds the administrator's password or the private key.
;;
;; Operator grant on the relay, for example:
;;   --connector-plugin-capability net.http
;;   --connector-plugin-capability-prefix net.http=appliance.example:443
;;
;; ABI (every argument an offset or length in this module's exported memory;
;; the result is 0 ok, 1 denied by the grant or the read-only test, 2 error):
;;   cap_http(req_ptr, req_len, out_ptr, out_cap, out_len_ptr) -> i32
;;     request: JSON {method, url, headers?, body? | body_input? | json?, auth?, auth_header?}
;;     response written at out_ptr: JSON {status, headers, body, truncated?}
;;   input_read(name_ptr, name_len, out_ptr, out_cap, out_len_ptr) -> i32
;;     (needs input.read) inputs: certificate_pem, fingerprint, target, target_config
(module
  (import "env" "cap_http"
    (func $cap_http (param i32 i32 i32 i32 i32) (result i32)))

  (memory (export "memory") 1)

  ;; The deploy request at offset 0 (182 bytes) and the test request
  ;; after it (87 bytes).
  (data (i32.const 0) "{\"method\":\"PUT\",\"url\":\"https://appliance.example/api/certificates/edge\",\"auth\":\"basic\",\"json\":{\"certificate\":{\"$input\":\"certificate_pem\"},\"private_key\":{\"$input\":\"private_key_pem\"}}}")
  (data (i32.const 182) "{\"method\":\"GET\",\"url\":\"https://appliance.example/api/certificates/edge\",\"auth\":\"basic\"}")

  ;; run() is the conformance entry point: nothing privileged.
  (func (export "run") (result i32)
    i32.const 0)

  ;; deploy() PUTs the certificate and key; the relay adds the credential.
  (func (export "deploy") (result i32)
    i32.const 0       ;; req_ptr
    i32.const 182     ;; req_len
    i32.const 16384   ;; out_ptr
    i32.const 32768   ;; out_cap
    i32.const 60000   ;; out_len_ptr
    call $cap_http)

  ;; test() runs read-only: a GET of what is installed. A PUT, POST or DELETE
  ;; here would be refused before it was sent.
  (func (export "test") (result i32)
    i32.const 182     ;; req_ptr
    i32.const 87      ;; req_len
    i32.const 16384   ;; out_ptr
    i32.const 32768   ;; out_cap
    i32.const 60000   ;; out_len_ptr
    call $cap_http))
