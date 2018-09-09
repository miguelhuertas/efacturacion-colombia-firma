using System;

namespace eFacturacionColombia
{
    public static class DateTimeHelper
    {
        /// <summary>
        /// Colombia TZ (-05:00:00): SA Pacific Standard Time
        /// </summary>
        public const string COLOMBIA_TIMEZONE_ID = "SA Pacific Standard Time";

        /// <summary>
        /// Obtiene la hora local de Colombia.
        /// </summary>
        public static DateTime GetColombianDate()
        {
            var timezone = TimeZoneInfo.FindSystemTimeZoneById(COLOMBIA_TIMEZONE_ID);

            return TimeZoneInfo.ConvertTime(DateTime.Now, timezone);
        }
    }
}