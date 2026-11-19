-- Indirizzo email secondario per il recupero dell'account (facoltativo, scelto dall'utente).
ALTER TABLE users ADD COLUMN recovery_email text;
