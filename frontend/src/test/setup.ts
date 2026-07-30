import "@testing-library/jest-dom/vitest";

class ResizeObserverMock implements ResizeObserver {
  public observe(): void {}
  public unobserve(): void {}
  public disconnect(): void {}
}

globalThis.ResizeObserver = ResizeObserverMock;

Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: (query: string): MediaQueryList => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false,
  }),
});
