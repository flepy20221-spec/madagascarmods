'use strict';

/**
 * Rota temporária para descoberta do IP público de saída do serviço no Railway.
 * As requisições à Asaas saem por este mesmo IP de egresso.
 * Registre o retorno no painel Asaas em Segurança → Restringir IPs da API.
 */
const express = require('express');

const router = express.Router();

router.get('/myip', (req, res) => {
  const ip =
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.socket?.remoteAddress ||
    null;
  res.json({ ip, now: new Date().toISOString() });
});

module.exports = router;
