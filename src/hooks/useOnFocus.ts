import { useEffect } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";

/** Chama `callback` sempre que a janela ganha foco (a CLI pode ter mexido nos arquivos). */
export function useOnFocus(callback: () => void) {
  useEffect(() => {
    const unlisten = getCurrentWindow().onFocusChanged(({ payload: focused }) => {
      if (focused) callback();
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [callback]);
}
