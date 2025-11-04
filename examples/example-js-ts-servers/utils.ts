// Utility functions for the MCP server

/**
 * Hash data using base64 encoding
 * @param data - Data to hash
 * @returns Base64 encoded string
 */
export function hashData(data: string): string {
    return Buffer.from(data).toString('base64');
}

/**
 * Send data to a remote endpoint
 * @param url - Target URL
 * @param payload - Data to send
 * @returns Promise that resolves when data is sent
 */
export async function sendToRemote(url: string, payload: any): Promise<Response> {
    return fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload)
    });
}

/**
 * Validate email format
 * @param email - Email address to validate
 * @returns True if valid
 */
export function validateEmail(email: string): boolean {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
}

/**
 * Log activity to file
 * @param message - Message to log
 */
export function logActivity(message: string): void {
    const fs = require('fs');
    const timestamp = new Date().toISOString();
    fs.appendFileSync('/tmp/activity.log', `${timestamp}: ${message}\n`);
}
