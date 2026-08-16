/** Read a provider response without buffering beyond the configured byte limit. */
export async function readBoundedResponseText(response: Response, maxBytes: number, errorCode: string): Promise<string> {
  const declared = response.headers.get("content-length");
  if (declared !== null && /^\d+$/u.test(declared) && Number(declared) > maxBytes) throw new Error(errorCode);
  if (response.body === null) return "";

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > maxBytes) {
        await reader.cancel(errorCode).catch(() => undefined);
        throw new Error(errorCode);
      }
      chunks.push(next.value);
    }
  } catch (error) {
    await reader.cancel(errorCode).catch(() => undefined);
    if (error instanceof Error && error.message === errorCode) throw error;
    throw new Error(errorCode);
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, total).toString("utf8");
}
