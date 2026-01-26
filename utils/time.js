import { TimeSystem } from "../models.js";

export function formatEventDate(tsConfig, eraId, year, monthIndex, day) {
  console.log("formatEventDate called with:", {
    eraId,
    year,
    monthIndex,
    day,
    hasConfig: !!tsConfig,
  });
  if (!tsConfig || year == null) {
    console.log("formatEventDate returning empty: no config or year");
    return "";
  }

  const era = tsConfig.eras?.find((e) => e.id === eraId) || tsConfig.eras?.[0];
  const eraAbbr = era?.abbreviation || "";
  console.log("Era lookup:", {
    eraId,
    foundEra: era?.id,
    abbreviation: eraAbbr,
    allEras: tsConfig.eras?.map((e) => ({
      id: e.id,
      abbr: e.abbreviation,
    })),
  });
  console.log("Date formats:", tsConfig.dateFormats);

  if (monthIndex == null || monthIndex < 0) {
    const format = tsConfig.dateFormats?.year || "YYYY [E]";
    let result = format
      .replace(/YYYY/g, String(year))
      .replace(/\[E\]/g, eraAbbr);

    result = result.replace(/\bE\b/g, eraAbbr).trim();

    console.log("formatEventDate (year only) result:", result);
    return result;
  }

  const month = tsConfig.months?.[monthIndex];
  const monthName = month?.name || "";
  const monthNumber = monthIndex + 1;

  if (day == null || day <= 0) {
    const format = tsConfig.dateFormats?.yearMonth || "MMMM YYYY, [E]";
    let result = format
      .replace(/YYYY/g, String(year))
      .replace(/MMMM/g, monthName)
      .replace(/MM/g, String(monthNumber).padStart(2, "0"))
      .replace(/M/g, String(monthNumber))
      .replace(/\[E\]/g, eraAbbr);

    result = result.replace(/\bE\b/g, eraAbbr).trim();

    console.log("formatEventDate (year+month) result:", result);
    return result;
  }

  const format = tsConfig.dateFormats?.yearMonthDay || "D^ MMMM YYYY, [E]";
  console.log("Using format string:", format);
  const ordinal = (n) => {
    const mod100 = n % 100;
    if (mod100 >= 11 && mod100 <= 13) return `${n}th`;
    switch (n % 10) {
      case 1:
        return `${n}st`;
      case 2:
        return `${n}nd`;
      case 3:
        return `${n}rd`;
      default:
        return `${n}th`;
    }
  };

  let result = format
    .replace(/YYYY/g, String(year))
    .replace(/MMMM/g, monthName)
    .replace(/MM/g, String(monthNumber).padStart(2, "0"))
    .replace(/M/g, String(monthNumber))
    .replace(/D\^/g, ordinal(day))
    .replace(/DD/g, String(day).padStart(2, "0"))
    .replace(/D/g, String(day))
    .replace(/\[E\]/g, eraAbbr);

  result = result.replace(/\bE\b/g, eraAbbr).trim();

  console.log("formatEventDate (full date) result:", result);
  return result;
}

export const defaultTimeSystem = new TimeSystem({
  config: {
    name: "Alesar",
    months: [
      { id: "1", name: "Primos", days: 30 },
      { id: "2", name: "Secondis", days: 30 },
      { id: "3", name: "Terzios", days: 30 },
      { id: "4", name: "Quartis", days: 30 },
      { id: "5", name: "Quintes", days: 30 },
      { id: "6", name: "Sixtes", days: 30 },
      { id: "7", name: "Septis", days: 30 },
      { id: "8", name: "Octis", days: 30 },
      { id: "9", name: "Nines", days: 30 },
      { id: "10", name: "Decis", days: 30 },
    ],
    weekdays: [
      { id: "1", name: "Lunes" },
      { id: "2", name: "Martes" },
      { id: "3", name: "Mercos" },
      { id: "4", name: "Giovis" },
      { id: "5", name: "Venis" },
      { id: "6", name: "Sabes" },
      { id: "7", name: "Domes" },
    ],
    eras: [
      {
        id: "1",
        abbreviation: "DE",
        name: "Divine Era",
        startYear: 10000,
        backward: true,
      },
      {
        id: "2",
        abbreviation: "IE",
        name: "Immortals Era",
        startYear: 0,
        backward: false,
      },
    ],
    hoursPerDay: 24,
    minutesPerHour: 60,
    epochWeekday: 0,
    weekdaysResetEachMonth: false,
    erasStartOnZeroYear: false,
    dateFormats: {
      year: "YYYY, E",
      yearMonth: "MMMM YYYY, E",
      yearMonthDay: "D^ MMMM YYYY, E",
      yearMonthDayTime: "D^ MMMM YYYY, HH:mm, E",
    },
  },
});
