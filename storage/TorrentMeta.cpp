/*
    This file is part of TON Blockchain Library.

    TON Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TON Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TON Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2017-2020 Telegram Systems LLP
*/

#include "TorrentMeta.hpp"

#include "td/utils/crypto.h"
#include "td/utils/UInt.h"

#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"
#include "vm/cellslice.h"

namespace ton {

td::Result<TorrentMeta> TorrentMeta::deserialize(td::Slice data) {
  TorrentMeta res;
  TRY_STATUS(td::unserialize(res, data));
  if (res.header) {
    td::Bits256 header_hash;
    td::sha256(td::serialize(res.header.value()), header_hash.as_slice());
    if (header_hash != res.info.header_hash) {
      return td::Status::Error("Header hash mismatch");
    }
  }
  if (res.root_proof.not_null()) {
    auto root = vm::MerkleProof::virtualize(res.root_proof, 1);
    if (root.is_null()) {
      return td::Status::Error("Root proof is not a merkle proof");
    }
    if (root->get_hash().as_slice() != res.info.root_hash.as_slice()) {
      return td::Status::Error("Root proof hash mismatch");
    }
  }
  res.info.init_cell();
  return res;
}

std::string TorrentMeta::serialize() const {
  return td::serialize(*this);
}
}  // namespace ton
