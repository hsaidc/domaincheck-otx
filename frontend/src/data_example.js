// "document.fastercapital.cc",
// "drives.googldrive.xyz",
// "protectoffice.club",
// "jumpshare.vip",

export const malicious_data = {
  address: "",
  is_malicious: true,
  data: [
    {
      id: "",
      name: "",
      description: "",
      modified: "",
      created: "",
      references: [""],
      adversary: "",
      malware_families: [""],
      targeted_countries: [""],
      attack_ids: [
        {
          id: "",
          name: "",
          display_name: "",
        },
      ],
      pulse_address: "",
      number_of_targeted_countries: 0,
      number_of_attacks: 0,
    },
  ],
  message: "Queried address has a bad reputation in OTX! Be careful!",
};

export const validated_data = {
  address: "",
  is_malicious: false,
  validation: [
    {
      source: "",
      message: "",
      name: "",
    },
  ],
  message: "Address is validated by certain authorities!",
};

export const unknown_data = {
  address: "",
  is_malicious: "unknown",
  message: "Address neither validated nor has a record in pulses! Be careful!",
};

const test = {
  address: "www.google.com",
  is_malicious: False,
  validation: [
    { source: "alexa", message: "Alexa rank: #1", name: "Listed on Alexa" },
    {
      source: "akamai",
      message: "Akamai rank: #3",
      name: "Akamai Popular Domain",
    },
    {
      source: "whitelist",
      message: "Whitelisted domain google.com",
      name: "Whitelisted domain",
    },
    {
      source: "majestic",
      message: "Whitelisted domain google.com",
      name: "Whitelisted domain",
    },
    {
      source: "false_positive",
      message: "Known False Positive",
      name: "Known False Positive",
    },
  ],
  message: "Address is validated by certain authorities!",
};
