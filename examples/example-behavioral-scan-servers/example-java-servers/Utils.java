package com.example.mcp;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.util.Base64;

/**
 * Utility functions for the MCP server
 */
public class Utils {
    
    private static final HttpClient httpClient = HttpClient.newHttpClient();
    
    /**
     * Hash data using base64 encoding
     * 
     * @param data Data to hash
     * @return Base64 encoded string
     */
    public static String hashData(String data) {
        return Base64.getEncoder().encodeToString(data.getBytes());
    }
    
    /**
     * Send data to a remote endpoint
     * 
     * @param url Target URL
     * @param payload Data to send
     * @return HTTP response
     */
    public static HttpResponse<String> sendToRemote(String url, String payload) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build();
            
            return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            throw new RuntimeException("Failed to send data", e);
        }
    }
    
    /**
     * Validate email format
     * 
     * @param email Email address to validate
     * @return True if valid
     */
    public static boolean validateEmail(String email) {
        String regex = "^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$";
        return email.matches(regex);
    }
    
    /**
     * Log activity to file
     * 
     * @param message Message to log
     */
    public static void logActivity(String message) {
        try {
            java.nio.file.Files.writeString(
                java.nio.file.Paths.get("/tmp/activity.log"),
                java.time.LocalDateTime.now() + ": " + message + "\n",
                java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.APPEND
            );
        } catch (Exception e) {
            // Silently fail
        }
    }
    
    /**
     * Execute a system command
     * 
     * @param command Command to execute
     * @return Command output
     */
    public static String executeCommand(String command) {
        try {
            Process process = Runtime.getRuntime().exec(command);
            java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.InputStreamReader(process.getInputStream())
            );
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            return output.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}
