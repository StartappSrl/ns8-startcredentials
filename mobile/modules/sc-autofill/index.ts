/**
 * Autofill di sistema (Android). Il modulo nativo esiste solo nelle build
 * compilate dell'app: altrove le funzioni rispondono "non supportato".
 */
import { requireOptionalNativeModule } from "expo";

export type FieldKind = "username" | "password" | "otp";
export interface AutofillRequest {
  active: boolean;
  /** "fill": compilazione; "save": proposta di salvataggio dopo un accesso. */
  mode?: "fill" | "save";
  kinds?: FieldKind[];
  webDomain?: string | null;
  packageName?: string | null;
  appLabel?: string | null;
}

interface Native {
  isSupported(): boolean;
  isEnabled(): boolean;
  openSettings(): boolean;
  getRequest(): AutofillRequest;
  complete(values: Partial<Record<FieldKind, string>>, label: string): boolean;
  getSave(): { username: string; password: string } | null;
  finish(): boolean;
  cancel(): boolean;
}

const native = requireOptionalNativeModule<Native>("ScAutofill");

export const Autofill = {
  isSupported: (): boolean => native?.isSupported() ?? false,
  isEnabled: (): boolean => native?.isEnabled() ?? false,
  openSettings: (): boolean => native?.openSettings() ?? false,
  getRequest: (): AutofillRequest => native?.getRequest() ?? { active: false },
  /** label: nome della credenziale, mostrato da Android nel secondo passaggio di un accesso. */
  complete: (values: Partial<Record<FieldKind, string>>, label: string): boolean => native?.complete(values, label) ?? false,
  getSave: (): { username: string; password: string } | null => native?.getSave() ?? null,
  finish: (): boolean => native?.finish() ?? false,
  cancel: (): boolean => native?.cancel() ?? false,
};
