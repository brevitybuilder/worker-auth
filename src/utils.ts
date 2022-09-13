import { Fido2Lib } from "fido2-lib/dist/main.js";

export const now = () => Math.floor(Date.now() / 1000);

export const makeFido = () => {
  const fido = new Fido2Lib({
    authenticatorUserVerification: 'preferred', // setting a value prevents warning in chrome
  });
  return fido;
}
