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

let test_keypair_curve curve =
  match keypair curve with
  | None -> assert false
  | Some (sk, pk) ->
    assert (equal sk sk) ;
    assert (equal pk pk) ;
    let pk' = neuterize sk in
    assert (equal pk pk')

let test_keypair_curve curve =
  for i = 0 to 1 do
    test_keypair_curve curve
  done

let test_keypair () =
  test_keypair_curve secp160r1 ;
  test_keypair_curve secp192r1 ;
  test_keypair_curve secp224r1 ;
  test_keypair_curve secp256r1 ;
  test_keypair_curve secp256k1 ;
  ()

let msg =
  Bigstring.of_string "Voulez-vous coucher avec moi, ce soir ?"

let test_sign_curve curve =
  match keypair curve with
  | None -> assert false
  | Some (sk, pk) ->
    let signature = Bigstring.create (pk_size curve) in
    begin match write_sign sk signature ~msg with
      | nb_written when nb_written = (pk_size curve) ->
        assert (verify pk ~msg ~signature)
      | _ -> assert false
    end ;
    match sign sk msg with
    | None -> assert false
    | Some signature ->
      assert (verify pk ~msg ~signature)

let test_sign_curve curve =
  for i = 0 to 1 do
    test_sign_curve curve
  done

let test_sign () =
  test_sign_curve secp160r1 ;
  test_sign_curve secp192r1 ;
  test_sign_curve secp224r1 ;
  test_sign_curve secp256r1 ;
  test_sign_curve secp256k1 ;
  ()

let basic = [
  "sksize", `Quick, test_sksize ;
  "pksize", `Quick, test_pksize ;
  "keypair", `Quick, test_keypair ;
  "sign", `Quick, test_sign ;
]

let () =
  Alcotest.run "uecc" [
    "basic", basic ;
  ]