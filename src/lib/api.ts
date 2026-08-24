/**
 * Helper to safely parse JSON response from fetch calls.
 * Prevents "Unexpected token 'T', 'The page c' ... is not valid JSON" errors when server returns HTML error pages or Vite SPA fallbacks.
 */
export async function safeJsonResponse<T = any>(response: Response, defaultError?: string): Promise<T> {
  const contentType = response.headers.get('content-type') || '';

  if (contentType.includes('application/json')) {
    try {
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data?.error || data?.message || defaultError || `Server error (${response.status})`);
      }
      return data;
    } catch (err: any) {
      if (err.message && !err.message.includes('JSON')) {
        throw err;
      }
      throw new Error(defaultError || 'Failed to parse JSON response from server.');
    }
  }

  // Response is not JSON (e.g. 404 HTML, 500 Error HTML, or Vite SPA fallback)
  const text = await response.text();
  const cleanSnippet = text.replace(/<[^>]*>/g, '').trim().substring(0, 120);

  if (!response.ok) {
    throw new Error(defaultError ? `${defaultError} (${response.status}: ${cleanSnippet || response.statusText})` : `Server error (${response.status}): ${cleanSnippet || response.statusText}`);
  }

  throw new Error(defaultError || `Server returned non-JSON response (${response.status}): ${cleanSnippet || 'Unexpected content'}`);
}
