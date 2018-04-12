(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

type curve

type secp160r1
type secp192r1
type secp224r1
type secp256r1
type secp256k1

type _ t =
  | Secp160r1 : curve -> secp160r1 t
  | Secp192r1 : curve -> secp192r1 t
  | Secp224r1 : curve -> secp224r1 t
  | Secp256r1 : curve -> secp256r1 t
  | Secp256k1 : curve -> secp256k1 t

external curve : int -> curve = "uECC_curve_stub"

let secp160r1 = Secp160r1 (curve 0)
let secp192r1 = Secp192r1 (curve 1)
let secp224r1 = Secp224r1 (curve 2)
let secp256r1 = Secp256r1 (curve 3)
let secp256k1 = Secp256k1 (curve 4)

let to_curve : type a. a t -> curve = function
  | Secp160r1 curve -> curve
  | Secp192r1 curve -> curve
  | Secp224r1 curve -> curve
  | Secp256r1 curve -> curve
  | Secp256k1 curve -> curve

external sk_size : curve -> int = "uECC_curve_private_key_size_stub" [@@noalloc]
external pk_size : curve -> int = "uECC_curve_public_key_size_stub" [@@noalloc]

let sk_size : type a. a t -> int = function
  | Secp160r1 curve -> sk_size curve
  | Secp192r1 curve -> sk_size curve
  | Secp224r1 curve -> sk_size curve
  | Secp256r1 curve -> sk_size curve
  | Secp256k1 curve -> sk_size curve

let pk_size : type a. a t -> int = function
  | Secp160r1 curve -> pk_size curve
  | Secp192r1 curve -> pk_size curve
  | Secp224r1 curve -> pk_size curve
  | Secp256r1 curve -> pk_size curve
  | Secp256k1 curve -> pk_size curve

external keypair :
  Bigstring.t -> Bigstring.t -> curve -> bool = "uECC_make_key_stub" [@@noalloc]

external pk_of_sk :
  Bigstring.t -> Bigstring.t -> curve -> bool = "uECC_compute_public_key_stub" [@@noalloc]
external valid_pk :
  Bigstring.t -> curve -> bool = "uECC_valid_public_key_stub" [@@noalloc]

external compress :
  Bigstring.t -> Bigstring.t -> curve -> unit = "uECC_compress" [@@noalloc]
external decompress :
  Bigstring.t -> Bigstring.t -> curve -> unit = "uECC_decompress" [@@noalloc]

type secret
type public

type (_, _) key =
  | Sk : Bigstring.t * 'a t -> ('a, secret) key
  | Pk : Bigstring.t * 'a t -> ('a, public) key

let neuterize : type a b. (a, b) key -> (a, public) key = function
  | Pk (buf, curve) -> Pk (buf, curve)
  | Sk (buf, curve) ->
    let pkbuf = Bigstring.create (pk_size curve) in
    let pk_computed_ok = pk_of_sk buf pkbuf (to_curve curve) in
    let pk_is_valid = valid_pk pkbuf (to_curve curve) in
    if not pk_computed_ok && pk_is_valid then
      invalid_arg "Uecc.neuterize" ;
    Pk (pkbuf, curve)

let sk_of_bytes :
  type a. a t -> Bigstring.t -> ((a, secret) key * (a, public) key) option =
  fun curve buf ->
    match curve with
    | Secp160r1 _curve -> begin
        if Bigstring.length buf
        match keypair sk pk curve with
        | true -> Some (Sk (sk, t), Pk (pk, t))
        | false -> None
      end

let keypair :
  type a. a t -> ((a, secret) key * (a, public) key) option = fun t ->
  let sklen = sk_size t in
  let pklen = pk_size t in
  let sk = Bigstring.create sklen in
  let pk = Bigstring.create pklen in
  match t with
  | Secp160r1 curve -> begin
    match keypair sk pk curve with
    | true -> Some (Sk (sk, t), Pk (pk, t))
    | false -> None
  end
  | Secp192r1 curve -> begin
    match keypair sk pk curve with
    | true -> Some (Sk (sk, t), Pk (pk, t))
    | false -> None
  end
  | Secp224r1 curve -> begin
    match keypair sk pk curve with
    | true -> Some (Sk (sk, t), Pk (pk, t))
    | false -> None
  end
  | Secp256r1 curve -> begin
    match keypair sk pk curve with
    | true -> Some (Sk (sk, t), Pk (pk, t))
    | false -> None
  end
  | Secp256k1 curve -> begin
    match keypair sk pk curve with
    | true -> Some (Sk (sk, t), Pk (pk, t))
    | false -> None
  end

(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff

   Permission to use, copy, modify, and/or distribute this software for any
   purpose with or without fee is hereby granted, provided that the above
   copyright notice and this permission notice appear in all copies.

   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
  ---------------------------------------------------------------------------*)
