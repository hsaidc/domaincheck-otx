/* eslint-disable react/prop-types */
// This component created as an example.
import { useEffect } from "react";
import { useTranslation } from "react-i18next";

const Dropdown = ({
  history,
  clearHistory,
  isHistoryOpen,
  setIsHistoryOpen,
  handlePreviousSearchClick,
}) => {
  const { t } = useTranslation();

  const handleDropdownClick = () => {
    if (isHistoryOpen) setIsHistoryOpen(false);
    else setIsHistoryOpen(true);
  };

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (
        isHistoryOpen &&
        !event.target.closest(".btn-primary-200") &&
        !event.target.closest("#previousSearch")
      ) {
        setIsHistoryOpen(false);
      }
    };

    document.addEventListener("click", handleClickOutside);

    return () => {
      document.removeEventListener("click", handleClickOutside);
    };
  }, [isHistoryOpen]);

  return (
    <div className="relative ml-2 mt-2 min-w-max text-left">
      <div>
        <button
          type="button"
          className="btn-primary-200 py-2"
          onClick={() => handleDropdownClick()}
        >
          {t("history")}
        </button>
      </div>

      <div
        className={`absolute right-0 z-10 mt-2 max-h-80 min-h-10 w-72 overflow-x-hidden overflow-y-hidden rounded-md bg-primary-300 bg-opacity-80 text-gray-100 shadow-md shadow-primary-500 ${isHistoryOpen ? "" : "hidden"}`}
      >
        <button
          className="btn-primary-200 ml-auto mr-1 mt-1 font-semibold shadow shadow-primary-500 hover:scale-[1.02]"
          onClick={clearHistory}
        >
          {t("clearHistory")}
        </button>
        <div className="mt-2 max-h-64 overflow-y-auto overflow-x-hidden">
          {history.length === 0 ? (
            <div className="ml-2 mt-1 cursor-pointer truncate rounded-lg py-1 pl-2">
              {/* <span className="pr-1">{history.length - index}.</span> */}
              <span className="">{t("noHistory")}</span>
            </div>
          ) : (
            history.toReversed().map((value, index) => (
              <div
                className="ml-2 w-full cursor-pointer rounded-lg py-1 pl-2 hover:scale-[1.03]"
                key={index}
                id="previousSearch"
                onClick={handlePreviousSearchClick}
              >
                {/* <span className="pr-1">{history.length - index}.</span> */}
                <span className="w-fit truncate">{value.text}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

export default Dropdown;
