// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "detail.hpp"

#include <iostream>

namespace iya::wsfed {
namespace {

const char *kUsage =
    "Usage:\n"
    "  wsfed-caep generate-keys --config <wsfed.json> [--cn <name>] [--days <n>] [--bits <n>] [--force]\n"
    "  wsfed-caep generate-keys --key <file> --cert <file> [--cn <name>] [--days <n>] [--bits <n>] [--force]\n"
    "      A new RSA key and a self-signed certificate, written where the configuration's privateKey and\n"
    "      certificate point (or to --key and --cert). Refuses to replace existing files without --force.\n"
    "      The key decrypts encrypted assertions and can authenticate the Shared Signals receiver (mutual\n"
    "      TLS); WS-Federation itself signs nothing. The common name defaults to one naming the realm.\n"
    "\n"
    "  wsfed-caep metadata --config <wsfed.json> [--out <file>]\n"
    "      This relying party's federation metadata, from the configuration (and its certificate, when it\n"
    "      has one): give it to the identity provider. Written to --out, or to standard output.";

std::string strip_file(std::string value) {
  if (value.compare(0, 5, "file:") == 0) return value.substr(5);
  return value;
}

}  // namespace

int CliMain(int argc, char **argv) {
  std::vector<std::string> args;
  for (int i = 0; i < argc; i++) args.emplace_back(argv[i] ? argv[i] : "");
  if (args.empty() || args[0] == "help" || (args.size() > 1 && args[1] == "--help")) {
    std::cout << kUsage << "\n";
    return 0;
  }
  std::string command = args[0];
  std::map<std::string, std::string> opt;
  for (size_t i = 1; i < args.size(); i++) {
    if (args[i].compare(0, 2, "--") != 0) {
      std::cerr << "unexpected argument " << args[i] << "\n\n" << kUsage << "\n";
      return 1;
    }
    std::string key = args[i].substr(2);
    if (key == "force" || key == "help") {
      opt[key] = "true";
      continue;
    }
    if (i + 1 >= args.size() || args[i + 1].compare(0, 2, "--") == 0) {
      std::cerr << "--" << key << " needs a value\n\n" << kUsage << "\n";
      return 1;
    }
    opt[key] = args[++i];
  }
  if (opt["help"] == "true") {
    std::cout << kUsage << "\n";
    return 0;
  }
  try {
    if (command == "generate-keys") {
      std::string key = opt["key"];
      std::string cert = opt["cert"];
      std::string common = opt["cn"];
      if (!opt["config"].empty()) {
        std::string raw = read_file(opt["config"]);
        if (raw.empty() && !file_exists(opt["config"])) {
          std::cerr << opt["config"] << " cannot be read\n";
          return 1;
        }
        Json parsed = parse_json(raw);
        std::string base = abs_path(opt["config"]);
        auto slash = base.find_last_of('/');
        base = slash == std::string::npos ? cwd_path() : base.substr(0, slash);
        auto at = [&](const std::string &value, const std::string &what) {
          if (value.empty() || value.find("-----BEGIN ") != std::string::npos) {
            throw std::runtime_error(opt["config"] + "'s " + what + " must be a file path for generate-keys to write to");
          }
          std::string path = strip_file(value);
          if (!path.empty() && path[0] == '/') return path;
          return join_path(base, path);
        };
        if (key.empty() && parsed.get("privateKey") && parsed.get("privateKey")->type == Json::String &&
            !parsed.get("privateKey")->text.empty()) {
          key = at(parsed.get("privateKey")->text, "privateKey");
        }
        if (cert.empty() && parsed.get("certificate") && parsed.get("certificate")->type == Json::String &&
            !parsed.get("certificate")->text.empty()) {
          cert = at(parsed.get("certificate")->text, "certificate");
        }
        if (common.empty() && parsed.get("realm") && parsed.get("realm")->type == Json::String && !parsed.get("realm")->text.empty()) {
          common = clip_runes("wsfed-caep-nodejs relying party " + parsed.get("realm")->text, 64);
        }
      }
      if (key.empty() || cert.empty()) {
        std::cerr << "generate-keys needs --config, or --key and --cert\n\n" << kUsage << "\n";
        return 1;
      }
      key = abs_path(key);
      cert = abs_path(cert);
      if (common.empty()) common = "wsfed-caep-nodejs relying party";
      if (opt["force"] != "true" && (file_exists(key) || file_exists(cert))) {
        std::string which = file_exists(key) ? key : cert;
        std::cerr << which << " already exists; pass --force to replace the key pair.\n"
                  << "Replacing it means giving the identity provider the new metadata before it next encrypts to this relying party.\n";
        return 1;
      }
      int days = 1095;
      int bits = 3072;
      if (opt.count("days")) {
        try {
          days = std::stoi(opt["days"]);
        } catch (...) {
          days = 0;
        }
        if (days <= 0) {
          std::cerr << "--days must be a positive whole number\n";
          return 1;
        }
      }
      if (opt.count("bits")) {
        try {
          bits = std::stoi(opt["bits"]);
        } catch (...) {
          bits = 0;
        }
        if (bits != 2048 && bits != 3072 && bits != 4096) {
          std::cerr << "--bits must be 2048, 3072 or 4096\n";
          return 1;
        }
      }
      KeyPairPem pair = CreateSelfSignedKeyPair(common, days, bits);
      write_file_mode(key, pair.private_key_pem, 0600);
      write_file_mode(cert, pair.certificate_pem, 0644);
      std::cout << "Wrote the private key  " << key << " (mode 600)\n";
      std::cout << "Wrote the certificate  " << cert << "\n";
      std::cout << "  subject   CN=" << pair.common_name << "\n";
      return 0;
    }
    if (command == "metadata") {
      if (opt["config"].empty()) {
        std::cerr << "metadata needs --config\n\n" << kUsage << "\n";
        return 1;
      }
      std::string raw = read_file(opt["config"]);
      if (raw.empty() && !file_exists(opt["config"])) {
        std::cerr << opt["config"] << " cannot be read\n";
        return 1;
      }
      Json parsed = parse_json(raw);
      std::vector<std::pair<std::string, Json>> kept;
      for (const auto &kv : parsed.obj) {
        if (kv.first != "idpCa") kept.push_back(kv);
      }
      parsed.obj.swap(kept);
      std::string base = abs_path(opt["config"]);
      auto slash = base.find_last_of('/');
      base = slash == std::string::npos ? cwd_path() : base.substr(0, slash);
      RelyingParty party = RelyingParty::Create(json_dump(parsed), base);
      std::string xml = party.Metadata();
      if (!opt["out"].empty()) {
        std::string path = abs_path(opt["out"]);
        write_file_mode(path, xml, 0644);
        std::cout << "Wrote the relying party metadata to " << path << "\n";
      } else {
        std::cout << xml;
      }
      return 0;
    }
  } catch (const std::exception &ex) {
    std::cerr << ex.what() << "\n";
    return 1;
  }
  std::cerr << "unknown command " << command << "\n\n" << kUsage << "\n";
  return 1;
}

}  // namespace iya::wsfed
