import { useState, useCallback, useRef } from "react";

const STORAGE_PREFIX = "col-width:";

function loadWidth(persistKey: string, initialWidth: number, minWidth: number): number {
  try {
    const raw = localStorage.getItem(STORAGE_PREFIX + persistKey);
    if (raw === null) return initialWidth;
    const val = Number(raw);
    if (!Number.isFinite(val) || val < minWidth) return initialWidth;
    return val;
  } catch {
    return initialWidth;
  }
}

function saveWidth(persistKey: string, width: number) {
  try {
    localStorage.setItem(STORAGE_PREFIX + persistKey, String(width));
  } catch { /* 静默降级 */ }
}

/**
 * @param initialWidth 初始宽度
 * @param direction "left" = 向左拖增大（Changes 列），"right" = 向右拖增大（Seq/Address 列）
 * @param minWidth 最小宽度
 * @param persistKey 可选，存在时自动从 localStorage 读写列宽
 */
export function useResizableColumn(
  initialWidth: number,
  direction: "left" | "right" = "left",
  minWidth = 40,
  persistKey?: string,
) {
  const [width, setWidth] = useState(() =>
    persistKey ? loadWidth(persistKey, initialWidth, minWidth) : initialWidth
  );
  const dragging = useRef(false);
  const startX = useRef(0);
  const startW = useRef(0);
  const latestWidth = useRef(width);
  latestWidth.current = width;

  const onMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    dragging.current = true;
    startX.current = e.clientX;
    startW.current = width;
    const onMove = (ev: MouseEvent) => {
      if (!dragging.current) return;
      const delta = direction === "left"
        ? startX.current - ev.clientX
        : ev.clientX - startX.current;
      const newW = Math.max(minWidth, startW.current + delta);
      setWidth(newW);
      latestWidth.current = newW;
    };
    const onUp = () => {
      dragging.current = false;
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      if (persistKey) saveWidth(persistKey, latestWidth.current);
    };
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  }, [width, direction, minWidth, persistKey]);

  const setWidthExternally = useCallback((newWidth: number) => {
    const clamped = Math.max(minWidth, newWidth);
    setWidth(clamped);
    latestWidth.current = clamped;
    if (persistKey) saveWidth(persistKey, clamped);
  }, [minWidth, persistKey]);

  return { width, onMouseDown, setWidth: setWidthExternally };
}
