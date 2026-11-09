package com.example;

import java.sql.Connection;
import java.sql.PreparedStatement;

/**
 * Fixture con SQL Injection real para PDGSEGSOFT-23. Cada linea vulnerable
 * reproduce el texto exacto que busca su regla (el motor compara por linea,
 * no por AST), y va acompanada de un near-miss seguro para medir precision.
 */
public class ReportController {

    public void unsafeCustomerLookup(Connection conn, javax.servlet.http.HttpServletRequest request) throws Exception {
        String sql = request.getParameter("id") + " /* built raw query */";
        conn.createStatement().executeQuery(sql);
    }

    public void listAllOrders(Connection conn) throws Exception {
        String sql = "SELECT * FROM orders";
        conn.createStatement().executeQuery(sql);
    }

    public void safeCustomerLookup(Connection conn, String customerId) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT id, name FROM customers WHERE id = ?");
        ps.setString(1, customerId);
        ps.executeQuery();
    }
}
