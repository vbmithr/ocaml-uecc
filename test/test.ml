open Uecc


let test_sksize () =
  ignore (sk_size secp160r1) ;
  ignore (sk_size secp192r1) ;
  ignore (sk_size secp224r1) ;
  ignore (sk_size secp256r1) ;
  ignore (sk_size secp256k1) ;
  ()

let test_pksize () =
  ignore (pk_size secp160r1) ;
  ignore (pk_size secp192r1) ;
  ignore (pk_size secp224r1) ;
  ignore (pk_size secp256r1) ;
  ignore (pk_size secp256k1) ;
  ()

let basic = [
  "sksize", `Quick, test_sksize ;
  "pksize", `Quick, test_pksize ;
]

let () =
  Alcotest.run "uecc" [
    "basic", basic ;
  ]
