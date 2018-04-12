(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

type secp160r1
type secp192r1
type secp224r1
type secp256r1
type secp256k1
(** Kinds of ECC curves. *)

type _ t
(** Type of an ECC curve, parametrized by its kind. *)

val secp160r1 : secp160r1 t
val secp192r1 : secp192r1 t
val secp224r1 : secp224r1 t
val secp256r1 : secp256r1 t
val secp256k1 : secp256k1 t
(** Supported curves. *)

val sk_size : _ t -> int
(** [sk_size] is the size in bytes of secret keys from [curve]. *)

val pk_size : _ t -> int
(** [pk_size] is the size in bytes of public keys from [curve]. *)

type secret
type public
type (_, _) key
(** Type of a key, parametrized by its curve and kind. *)

val neuterize : ('a, _) key -> ('a, public) key
(** [neuterize k] is [k] if [k] is public, or is the associated public
    key of [k] if [k] is secret. *)

val sk_of_bytes :
  'a t -> Bigstring.t -> (('a, secret) key * ('a, public) key) option
(** [sk_of_bytes curve buf] is [Some (sk, pk)] if [buf] contains a
    valid serialization of a [curve] secret key, or [None] otherwise. *)

val pk_of_bytes : 'a t -> Bigstring.t -> ('a, public) key option
(** [pk_of_bytes curve buf] is [Some pk] if [buf] contains a valid
    serialization of a [curve] public key, or [None] otherwise. *)

val to_bytes : (_, _) key -> Bigstring.t
(** [to_bytes k] is a serialization of [k]. *)

val write_key : Bigstring.t -> (_, _) key -> int
(** [write_key buf k] writes [k] at [buf] and returns the number of
    bytes actually written. *)

val keypair : 'a t -> (('a, secret) key * ('a, public) key) option
(** [keypair curve] is [Some (sk, pk)] where [sk] and [pk] is freshly
    generated keypair for [curve] if everything went well, or [None]
    otherwise. *)

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
