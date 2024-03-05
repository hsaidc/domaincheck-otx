const en = {
  translation: {
    // Query and history
    query: "Query",
    queryBarPlaceholder: "Enter a domain name or IPv4 address...",
    history: "History",
    noHistory: "You haven't made any queries yet...",
    clearHistory: "Clear History",

    // Default states
    initialQueryMessage:
      "Please enter a valid IPv4 address or domain name to query. If you have made previous queries, you can access the results via the 'History' button.",
    wrongQueryMessage:
      "Please enter a valid IPv4 address or domain name to query.",

    // Figures
    queryLabel: "Query Statistics",
    malicious: "Malicious",
    notMalicious: "Safe",
    unknown: "Unknown",
    figureExplanationTooltip:
      "A pie chart showing the statistics of all your queries. Your queries will be classified as malicious, safe, or unknown based on the records in the OTX database.",

    // Results
    OTXQueryResultButton: "Open Threat Exchange Query",
    DNSEnumerationResultButton: "DNS Enumeration Result",
    OTXValidators: "Validators",
    OTXPulseRecords: "Pulse Records",

    // Pulse Details
    pulseName: "Pulse Name",
    pulseURL: "Pulse URL",
    pulseCreated: "Created",
    pulseModified: "Modified",
    pulseDescription: "Description",
    pulseReferences: "References",

    // Validator Details
    validationSource: "Validator Source",
    validationMessage: "Validator Message",

    // DNS Enumeration Results
    DNSEnumerationEmpty:
      "No information could be obtained as a result of the DNS enumeration process.",
  },
};

export default en;
