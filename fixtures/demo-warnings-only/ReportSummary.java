package com.example;

import java.sql.Connection;

/** Demo "con warnings" para PDGSEGSOFT-23: solo severidad MEDIUM a propósito. */
public class ReportSummary {

    public void listAllOrders(Connection conn) throws Exception {
        String sql = "SELECT * FROM orders";
        conn.createStatement().executeQuery(sql);
    }
}
