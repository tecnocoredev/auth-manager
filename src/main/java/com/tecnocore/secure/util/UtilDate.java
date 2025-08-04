package com.tecnocore.secure.util;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class UtilDate {
    private static final DateTimeFormatter OUTPUT_FORMATTER = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss");

    /**
     * Formatea un objeto LocalDateTime a una cadena con el formato "dd-MM-yyyy HH:mm:ss".
     *
     * @param dateTime El objeto LocalDateTime a formatear.
     * @return Una cadena que representa la fecha y hora formateada.
     */
    public static String formatDateTime(LocalDateTime dateTime) {
        return dateTime.format(OUTPUT_FORMATTER);
    }
}
