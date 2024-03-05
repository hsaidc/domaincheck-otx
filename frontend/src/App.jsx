// Application provided as single page without using components to ease review process and undertanding data flow
// Only two components added as an example.
import { useEffect, useState } from "react";
import axios from "axios";

// Localization
import "./i18next.conf";
import { useTranslation } from "react-i18next";

// Figures
import { Tooltip } from "react-tooltip";
import { PieChart, pieArcLabelClasses } from "@mui/x-charts/PieChart";

// Custom components
import Dropdown from "./components/Dropdown";
import Spin from "./components/icons/Spin";

const apiEndpoint = import.meta.env.VITE_API_URL;

console.log("API Endpoint:", apiEndpoint);
function App() {
  // State variables to process website
  const { t } = useTranslation();
  const [text, setText] = useState("");
  const [previousSearchText, setPreviousSearchText] = useState("");
  const [processing, setProcessing] = useState(false);
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [selectedPulse, setSelectedPulse] = useState({});
  const [selectedValidation, setSelectedValidation] = useState({});
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [activeTab, setActiveTab] = useState("otx");

  // State variables to store data
  const [previousSearch, setPreviousSearch] = useState([]);
  const [statistics, setStatistics] = useState([]);
  const [DNSEnumerationResult, setDNSEnumerationResult] = useState([]);
  const [OTXQueryResult, setOTXQueryResult] = useState({
    address: "",
    is_malicious: "unknown",
    data: [],
    message: t("initialQueryMessage"),
  });

  const onSubmit = async () => {
    try {
      setProcessing(true);

      // Check is address already exists in the history
      // This might be disabled if user want so query again at different time instead of fetching from history.
      const previousResult = previousSearch.find((elem) => elem.text === text);
      if (previousResult) {
        // Get OTX data from memory.
        setOTXQueryResult(previousResult.OTXData);

        // Reset selected index to first validation or pulse
        setSelectedIndex(0);
        if (previousResult.OTXData.is_malicious === false)
          setSelectedValidation(previousResult.OTXData.validation[0]);
        if (previousResult.OTXData.is_malicious === true)
          setSelectedPulse(previousResult.OTXData.data[0]);

        // Get DNS enumeration data from memory
        setDNSEnumerationResult(previousResult.DNSEnumerationData ?? []);
        setProcessing(false);

        return; // Do not fetch result again
      }

      // Query OTX database
      const otx_response = await axios.get(`${apiEndpoint}/otx`, {
        timeout: 5000,
        params: {
          address: text,
          language: localStorage.getItem("i18nextLng").split("-")[0] ?? "en",
        },
      });

      // Query for DNS enumeration
      const dns_enumeration_response = await axios.get(`${apiEndpoint}/dns`, {
        timeout: 300000,
        params: {
          address: text,
          language: localStorage.getItem("i18nextLng").split("-")[0] ?? "en",
        },
      });

      // Update state variables representing OTX data
      // If query status is false, that means something went wrong at the backend
      // However, backend was able to response the query.
      // Hence inform user to try again
      let OTXData = [];
      if (otx_response?.data?.status) {
        OTXData = otx_response?.data?.data;
        setOTXQueryResult(OTXData);
      } else
        setOTXQueryResult({
          address: "",
          is_malicious: "unknown",
          data: [],
          message: t("wrongQueryMessage"),
        });

      // Update state variables representing DNS enumeration
      // If query status is false, that means something went wrong at the backend
      // However, backend was able to response the query.
      let DNSEnumerationData = [];
      if (dns_enumeration_response?.data?.status) {
        DNSEnumerationData = dns_enumeration_response?.data?.data;
        setDNSEnumerationResult(DNSEnumerationData);
      } else setDNSEnumerationResult([]);

      // Classify OTX response as malicious, not malicious or unknown to visualize the results
      // ALWAYS: id: 0 -> malicious, id: 1 -> not malicious, id: 2 -> unknown
      const tmpStatistics = statistics; // dummy variable
      if (OTXData.is_malicious === true) {
        setSelectedPulse(OTXData.data[0]);
        // Find index of the malicious data in the state variable
        const id = 0;
        const elementToUpdate = tmpStatistics.findIndex(
          (item) => item.id === id,
        );

        // If already exsist, just update its value
        if (elementToUpdate !== -1) {
          tmpStatistics[elementToUpdate].value =
            tmpStatistics[elementToUpdate].value + 1;
        } else {
          // If not exists in the array, create its first record
          tmpStatistics.push({
            id: 0,
            value: 1,
            label: t("malicious"),
            color: "#991b1b",
          });
        }
        setStatistics(tmpStatistics);
      } else if (OTXData.is_malicious === false) {
        setSelectedValidation(OTXData.validation[0]);
        // Find index of the malicious data in the state variable
        const id = 1;
        const elementToUpdate = tmpStatistics.findIndex(
          (item) => item.id === id,
        );

        // If already exsist, just update its value
        if (elementToUpdate !== -1) {
          tmpStatistics[elementToUpdate].value =
            tmpStatistics[elementToUpdate].value + 1;
        } else {
          // If not exists in the array, create its first record
          tmpStatistics.push({
            id: 1,
            value: 1,
            label: t("notMalicious"),
            color: "#365314",
          });
        }
        setStatistics(tmpStatistics);
      } else if (OTXData.is_malicious === "unknown") {
        // Find index of the malicious data in the state variable
        const id = 2;
        const elementToUpdate = tmpStatistics.findIndex(
          (item) => item.id === id,
        );

        // If already exsist, just update its value
        if (elementToUpdate !== -1) {
          tmpStatistics[elementToUpdate].value =
            tmpStatistics[elementToUpdate].value + 1;
        } else {
          // If not exists in the array, create its first record
          tmpStatistics.push({
            id: 2,
            value: 1,
            label: t("unknown"),
            color: "#4b5563",
          });
        }
        // Update state variable with dummy variable
        setStatistics(tmpStatistics);
      } else {
        throw new Error("Could not understand classification of the query!");
      }

      // Add search to history
      // If search is not already added to previous search list and history size less than 50
      if (
        previousSearch.filter((elem) => elem.text === text).length === 0 &&
        previousSearch.length < 50
      ) {
        setPreviousSearch((prev) => [
          ...prev,
          {
            text: text,
            OTXData: OTXData,
            DNSEnumerationData: DNSEnumerationData,
          },
        ]);
      } else if (
        // If search is not already added to previous search list and history size equals to 50. Only last 50 queries stored in the history.
        previousSearch.filter((elem) => elem.text === text).length === 0 &&
        previousSearch.length == 50
      ) {
        // Remove the oldest element in the history and push latest search
        setPreviousSearch((prev) => [
          ...prev.slice(1),
          {
            text: text,
            OTXData: OTXData,
            DNSEnumerationData: DNSEnumerationData,
          },
        ]);
      }
      // Clear state variables
      setText("");
      setProcessing(false);
    } catch (err) {
      console.error(err);
      setOTXQueryResult({
        address: "",
        is_malicious: "unknown",
        data: [],
        message: t("wrongQueryMessage"),
      });

      setDNSEnumerationResult([]);
      setPreviousSearchText("");
      setProcessing(false);
      // setText(
      // "Sorgunuz başarısız oldu. Lütfen geçerli bir IPv4 adresi ya da alan adı girdiğinizden emin olunuz.",
      // );
    }
  };

  const handlePreviousSearchClick = (e) => {
    setText(e.target.textContent);
    setPreviousSearchText(e.target.textContent); // A UseEffect hook handles rest of the updates.
  };

  // Submits given address if user presses enter insted of clicking the button
  const handleEnter = (e) => {
    e.preventDefault();
    if (e.key === "Enter") {
      onSubmit(text);
    }
  };

  // Handles clear history operation
  const clearHistory = () => {
    setPreviousSearch([]);
    setStatistics([]);
    setOTXQueryResult({
      address: "",
      is_malicious: "unknown",
      data: [],
      message: t("initialQueryMessage"),
    });
    setDNSEnumerationResult([]);
    localStorage.setItem("previousSearch", JSON.stringify([]));
    localStorage.setItem("previousStats", JSON.stringify([]));
  };

  // Provides navigation between different pulse records
  const handlePulseClick = (e, index) => {
    setSelectedPulse(OTXQueryResult?.data[index]);
    setSelectedIndex(index);
  };

  // Provides navigation between different validation records
  const handleValidationClick = (e, index) => {
    setSelectedValidation(OTXQueryResult?.validation[index]);
    setSelectedIndex(index);
  };

  // Provides navigation between OTX and DNS queries
  const handleTabClick = (tabName) => {
    setActiveTab(tabName);
  };

  // Load history on startup
  useEffect(() => {
    const previousSearchFromLocalStorage = JSON.parse(
      localStorage.getItem("previousSearch"),
    );
    const previousStatsFromLocalStorage = JSON.parse(
      localStorage.getItem("previousStats"),
    );
    if (previousStatsFromLocalStorage)
      setPreviousSearch(previousSearchFromLocalStorage);
    if (previousSearchFromLocalStorage)
      setStatistics(previousStatsFromLocalStorage);
  }, []);

  // Update local storage items as user performs a new successfull query
  useEffect(() => {
    if (previousSearch.length !== 0) {
      localStorage.setItem("previousSearch", JSON.stringify(previousSearch));
      localStorage.setItem("previousStats", JSON.stringify(statistics));
    }
  }, [previousSearch, statistics]);

  // Handles navigation in history
  useEffect(() => {
    const previousResult = previousSearch.find((elem) => elem.text === text);
    if (previousResult) {
      setOTXQueryResult(previousResult.OTXData);
      setDNSEnumerationResult(previousResult.DNSEnumerationData);
      setSelectedIndex(0);
      if (previousResult.OTXData.is_malicious === false)
        setSelectedValidation(previousResult.OTXData.validation[0]);
      if (previousResult.OTXData.is_malicious === true)
        setSelectedPulse(previousResult.OTXData.data[0]);
    }
  }, [previousSearchText]);

  return (
    <div className="flex h-screen min-h-[800px] w-screen min-w-[375] flex-col items-center overflow-auto bg-primary-500 text-gray-200">
      <div className="bg-tones-9 my-10 mb-5 flex h-fit min-h-[90%] w-[95%] min-w-[350px] flex-col items-center rounded-2xl shadow-md shadow-primary-300 ring-1 ring-primary-300 ring-opacity-80 xl:h-fit xl:w-4/5">
        <div className="flex h-fit w-[95%] flex-col flex-wrap items-center justify-center border-b-2 border-primary-300 py-2">
          <div className="flex-rco flex w-[95%] flex-wrap items-center justify-center">
            <input
              type="text"
              value={text}
              placeholder={t("queryBarPlaceholder")}
              className="mt-2 w-[70%] min-w-72 rounded-lg border-2 border-gray-500 bg-gray-800 py-2 pl-3 text-base focus:border-blue-600"
              onChange={(e) => {
                e.preventDefault(), setText(e.target.value);
              }}
              onKeyUp={(e) => handleEnter(e)}
            />
            <button
              type="submit"
              className="btn-primary-200 ml-3 mt-2 w-20 py-2"
              onClick={onSubmit}
            >
              {processing ? (
                <Spin className="animate-spin text-gray-200" />
              ) : (
                <span>{t("query")}</span>
              )}
            </button>
            <Dropdown
              history={previousSearch}
              clearHistory={clearHistory}
              isHistoryOpen={isHistoryOpen}
              setIsHistoryOpen={setIsHistoryOpen}
              handlePreviousSearchClick={handlePreviousSearchClick}
            />
          </div>
          <div
            className="flex h-[220px] min-w-[220px] flex-1 items-center justify-center"
            data-tooltip-id="chart-tooltip"
            data-tooltip-content={t("figureExplanationTooltip")}
            data-tooltip-place="right"
          >
            <Tooltip
              id="chart-tooltip"
              style={{
                backgroundColor: "#3C678C",
                color: "white",
                outline: "solid",
                outlineColor: "#3C678C",
                outlineWidth: "1px",
                textWrap: true,
                textAlign: "center",
                width: "300px",
              }}
            />
            {statistics.length > 0 ? (
              <PieChart
                colors={["#991b1b", "#365314", "$4b5563"]}
                width={220}
                height={220}
                series={[
                  {
                    data: statistics,
                    outerRadius: 100,
                    cx: 110,
                    cy: 110,
                    arcLabel: (item) => `${item.value}`,
                    highlightScope: { faded: "global", highlighted: "item" },
                    faded: {
                      additionalRadius: -10,
                      color: "gray",
                    },
                  },
                ]}
                sx={{
                  [`& .${pieArcLabelClasses.root}`]: {
                    fill: "white",
                    fontWeight: "bold",
                  },
                }}
                slotProps={{
                  legend: { hidden: true },
                }}
              />
            ) : (
              <PieChart
                skipAnimation={true}
                colors={["#4b5563"]}
                width={220}
                height={220}
                series={[
                  {
                    data: [
                      {
                        id: 0,
                        value: 1,
                        label: t("queryLabel"),
                        color: "#4b5563",
                      },
                    ],
                    outerRadius: 100,
                    cx: 110,
                    cy: 110,
                    arcLabel: (item) => `${item.label}`,
                  },
                ]}
                sx={{
                  [`& .${pieArcLabelClasses.root}`]: {
                    fill: "white",
                    fontWeight: "bold",
                  },
                }}
                slotProps={{
                  legend: { hidden: true },
                }}
              />
            )}
          </div>
        </div>

        <div className="flex h-1/2 w-[98%] flex-1 flex-col p-5">
          <div
            className={`rounded-2xlpx-3 flex min-h-fit flex-col items-center py-3 shadow-md`}
          >
            <div className="mb-5 flex h-20 min-h-fit w-full flex-row flex-wrap items-center justify-evenly rounded-3xl ">
              <div
                className={`flex min-h-12 w-[40%] cursor-pointer items-center justify-center rounded-2xl text-center text-lg font-medium shadow shadow-primary-300  ring-1 ring-primary-300 ring-opacity-80 hover:scale-105 ${activeTab === "otx" ? "scale-105" : ""}`}
                onClick={() => handleTabClick("otx")}
              >
                <span>{t("OTXQueryResultButton")}</span>
              </div>
              <div
                className={`flex min-h-12 w-[40%] cursor-pointer items-center justify-center rounded-2xl text-center text-lg font-medium shadow shadow-primary-300 ring-1 ring-primary-300 ring-opacity-80 hover:scale-105 ${activeTab === "dns" ? "scale-105" : ""}`}
                onClick={() => handleTabClick("dns")}
              >
                <span>{t("DNSEnumerationResultButton")}</span>
              </div>
            </div>
            <div className="my-2 flex flex-row items-center justify-center gap-y-2 text-lg ">
              <span className="mr-2">{OTXQueryResult.address}</span>
              {OTXQueryResult.is_malicious == true ? (
                <i className="fa-solid fa-circle-exclamation fa-2xl flex h-[30px] w-[30px] items-center justify-center rounded-full bg-white text-red-800 "></i>
              ) : OTXQueryResult.is_malicious == false ? (
                <i className="fa-solid fa-circle-check fa-2xl flex h-[30px] w-[30px] items-center justify-center rounded-full bg-white text-lime-800 "></i>
              ) : (
                <i className="fa-solid fa-circle-question fa-2xl flex h-[30px] w-[30px] items-center justify-center rounded-full bg-white text-primary-500 "></i>
              )}
            </div>
            <div className="px-4 text-lg ">
              <span className="mr-2">{OTXQueryResult.message}</span>
            </div>

            {activeTab === "otx" ? (
              <>
                <div
                  className={`max-h-48 w-full flex-col items-center rounded-xl px-2 py-2 sm:max-h-56 md:max-h-64 lg:max-h-72 ${OTXQueryResult.is_malicious === "unknown" ? "hidden" : "flex"}`}
                >
                  <div
                    id="ValidationPulseHeader"
                    className={`flex h-14 w-full items-center justify-center border-primary-400  pb-1`}
                  >
                    <div className="grid w-full auto-cols-max grid-flow-col items-center justify-start gap-x-2.5 overflow-x-auto overflow-y-hidden px-1 pb-1">
                      {OTXQueryResult.is_malicious === false ? (
                        <>
                          <span className="mt-1 text-lg font-semibold">
                            {t("OTXValidators")}
                            <i className="fa-solid fa-right-long pl-2 "></i>
                          </span>
                          {OTXQueryResult.validation?.map((value, index) => (
                            <div
                              className={`mb-1 mt-1 cursor-pointer rounded-lg px-2 py-1 shadow shadow-primary-300 ring-1 ring-primary-300 ring-opacity-80  hover:scale-110 ${selectedIndex === index ? "scale-110" : ""}`}
                              key={index}
                              onClick={(e) => handleValidationClick(e, index)}
                            >
                              {/* <span className='pr-1'>{history.length - index}.</span> */}
                              <span className="truncate">{value.source}</span>
                            </div>
                          ))}
                        </>
                      ) : OTXQueryResult.is_malicious === true ? (
                        <>
                          <span className="mt-1 text-lg font-semibold">
                            {t("OTXPulseRecords")}
                            <i className="fa-solid fa-right-long pl-2 "></i>
                          </span>
                          {OTXQueryResult.data?.map((value, index) => (
                            <div
                              className={`mb-2 mt-2 cursor-pointer rounded-lg px-2 py-1 shadow shadow-primary-300 ring-1 ring-primary-300 ring-opacity-80  hover:scale-110 ${selectedIndex === index ? "scale-110" : ""}`}
                              key={index}
                              onClick={(e) => handlePulseClick(e, index)}
                            >
                              {/* <span className='pr-1'>{history.length - index}.</span> */}
                              <span>Pulse {index}</span>
                            </div>
                          ))}
                        </>
                      ) : null}
                    </div>
                  </div>
                  {OTXQueryResult.is_malicious === true ? (
                    <div className=" flex max-h-72 w-full flex-col justify-items-start gap-y-2 overflow-y-auto  overflow-x-hidden p-2">
                      <div className="flex flex-row gap-y-2">
                        <div className="mr-3 w-[45%]">
                          <p className="font-bold">{t("pulseName")}</p>
                          <p className="pl-1">
                            {" "}
                            {selectedPulse?.name ?? t("notSpecified")}{" "}
                          </p>
                        </div>
                        <div className="w-[45%] truncate">
                          <p className="font-bold">{t("pulseURL")}</p>
                          <a
                            className=" pl-1 underline"
                            target="_blank"
                            rel="noopener noreferrer"
                            href={selectedPulse?.pulse_address ?? ""}
                          >
                            {selectedPulse?.pulse_address ?? t("notSpecified")}
                          </a>
                        </div>
                      </div>
                      <div className="flex flex-row">
                        <div className="mr-3 w-[45%]">
                          <p className="font-bold">{t("pulseCreated")}</p>
                          <p className="pl-1">
                            {" "}
                            {selectedPulse?.created != ""
                              ? selectedPulse.created
                              : t("notSpecified")}
                          </p>
                        </div>
                        <div className="w-[45%]">
                          <p className="font-bold">{t("pulseModified")}</p>
                          <p className="pl-1">
                            {selectedPulse?.modified != ""
                              ? selectedPulse.modified
                              : t("notSpecified")}
                          </p>
                        </div>
                      </div>
                      <div className="col-span-full">
                        <span className="font-bold">
                          {t("pulseDescription")}:{" "}
                        </span>
                        <span>
                          {selectedPulse?.description != ""
                            ? selectedPulse?.description
                            : t("notSpecified")}
                        </span>
                      </div>
                      <div className="col-span-full">
                        <span className="font-bold">
                          {t("pulseReferences")}:{" "}
                        </span>
                        <span>
                          {selectedPulse?.references.length
                            ? selectedPulse?.references.join("\n")
                            : t("notSpecified")}
                        </span>
                      </div>
                    </div>
                  ) : (
                    <div className="flex w-full flex-col justify-items-start overflow-y-auto  overflow-x-hidden p-2">
                      <div className="flex flex-col gap-y-2">
                        <div className="mr-3 w-full">
                          <span className="font-bold">
                            {t("validationSource")}:{" "}
                          </span>
                          <span> {selectedValidation?.source ?? ""} </span>
                        </div>
                        <div className="mr-3 w-full">
                          <span className="font-bold">
                            {t("validationMessage")}:{" "}
                          </span>
                          <span> {selectedValidation?.message ?? ""} </span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </>
            ) : (
              <div
                className={`mt-2 max-h-40 w-full flex-col items-start gap-y-2 divide-y-2 overflow-y-auto rounded-xl px-2 py-2 sm:max-h-52 md:max-h-64 lg:max-h-72 ${OTXQueryResult.address.length !== 0 ? "flex" : "hidden"}`}
              >
                {DNSEnumerationResult.filter((elem) => elem.status === true)
                  .length === 0 ? (
                  <div className="mt-5 flex w-full items-center justify-center">
                    <span className="w-fit border-y-2 py-2 text-center text-xl font-medium">
                      {t("DNSEnumerationEmpty")}
                    </span>
                  </div>
                ) : (
                  <>
                    {DNSEnumerationResult.filter(
                      (elem) => elem.status === true,
                    ).map((value, index) => (
                      <p
                        className="w-full break-words pt-2"
                        key={index}
                      >{`${value.record_type}: ${value.data.join(", ")}`}</p>
                    ))}
                  </>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
