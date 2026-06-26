(module
  (import "env" "cap_write" (func $cap_write (param i32) (result i32)))
  (func (export "run") (result i32)
    i32.const 1
    call $cap_write))
