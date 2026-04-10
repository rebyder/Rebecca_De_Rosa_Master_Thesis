# Valutazione Comparativa di Agenti di Rilevamento CWE

## Riepilogo Esecutivo

Questa valutazione confronta le prestazioni di due agenti di rilevamento vulnerabilità (CWE - Common Weakness Enumeration) su un dataset di 25 file di codice sorgente.

---

## 1. Metriche Globali di Prestazione

### Agent (Agente Personalizzato)

| Metrica | Valore |
|---------|--------|
| **Precision** | 66.7% |
| **Recall** | 32.0% |
| **F1-Score** | 43.2% |
| **True Positives (TP)** | 8 |
| **False Positives (FP)** | 4 |
| **False Negatives (FN)** | 17 |

**Interpretazione:** L'agente personalizzato mostra una precisione moderata (66.7%), ma una recall limitata (32%), indicando che individua correttamente le vulnerabilità rilevate, ma ne manca molte.

### CodeQL (Strumento Statico)

| Metrica | Valore |
|---------|--------|
| **Precision** | 16.7% |
| **Recall** | 8.0% |
| **F1-Score** | 10.8% |
| **True Positives (TP)** | 2 |
| **False Positives (FP)** | 10 |
| **False Negatives (FN)** | 23 |

**Interpretazione:** CodeQL ha prestazioni significativamente inferiori, con una precisione molto bassa (16.7%) e una recall ancora più bassa (8%). Genera molti falsi positivi e manca la maggior parte delle vulnerabilità.

---

## 2. Confronto Sintetico

```
Metriche di Prestazione a Confronto
╔════════════════════╦════════════════╦════════════════╗
║  Metrica           ║  Agent         ║  CodeQL        ║
╠════════════════════╬════════════════╬════════════════╣
║  Precision         ║  66.7% ▲       ║  16.7%         ║
║  Recall            ║  32.0% ▲       ║  8.0%          ║
║  F1-Score          ║  43.2% ▲       ║  10.8%         ║
║  TP (Corretti)     ║  8 ▲           ║  2             ║
║  FP (Falsi Allarmi)║  4 ▼           ║  10 ▲          ║
║  FN (Mancati)      ║  17 ▼          ║  23 ▲          ║
╚════════════════════╩════════════════╩════════════════╝
```

**Conclusione:** L'Agent è **4x superiore** a CodeQL in termini di F1-Score (43.2% vs 10.8%).

---

## 3. Analisi per Categoria di Risultati

### Agent

| Risultato | Numero | Percentuale |
|-----------|--------|-------------|
| Exact Matches (Corretti) | 6 | 24.0% |
| Partial Matches (Parziali) | 2 | 8.0% |
| Complete Misses (Completamente Mancati) | 16 | 64.0% |
| Over-Detections | 0 | 0.0% |

### CodeQL

| Risultato | Numero | Percentuale |
|-----------|--------|-------------|
| Exact Matches (Corretti) | 1 | 4.0% |
| Partial Matches (Parziali) | 1 | 4.0% |
| Complete Misses (Completamente Mancati) | 19 | 76.0% |
| Over-Detections | 0 | 0.0% |

---

## 4. Analisi per Tipo di Vulnerabilità

### CWE-22 (Path Traversal)

**Dataset:** 5 file con vulnerabilità CWE-22

| Agente | TP | FP | FN | Precision | Recall |
|--------|----|----|----|-----------|----|
| Agent | 1 | 0 | 4 | 100% | 20% |
| CodeQL | 1 | 0 | 4 | 100% | 20% |

**Analisi:** Entrambi gli agenti hanno prestazioni identiche su CWE-22, individuando solo 1 su 5 vulnerabilità.

### CWE-89 (SQL Injection)

**Dataset:** 12 file con vulnerabilità CWE-89

| Agente | TP | FP | FN | Precision | Recall |
|--------|----|----|----|-----------|----|
| Agent | 6 | 3 | 6 | 66.7% | 50.0% |
| CodeQL | 1 | 7 | 11 | 12.5% | 8.3% |

**Analisi:** L'Agent ha prestazioni notevolmente migliori su CWE-89, con recall del 50% vs 8.3% di CodeQL.

### CWE-79 (Cross-Site Scripting)

**Dataset:** 8 file con vulnerabilità CWE-79

| Agente | TP | FP | FN | Precision | Recall |
|--------|----|----|----|-----------|----|
| Agent | 1 | 1 | 7 | 50% | 12.5% |
| CodeQL | 0 | 3 | 8 | 0% | 0% |

**Analisi:** L'Agent individua almeno 1 vulnerabilità CWE-79, mentre CodeQL fallisce completamente (0 corretti).

---

## 5. Dettagli dei Risultati per File

### ✅ File con Identificazione Corretta (Agent)

| File | CWE Vulnerabile | Stato |
|------|-----------------|-------|
| cwefixes/nova/image/s3.py | CWE-22 | ✓ Exact Match |
| cwefixes/mod_fun/__init__.py | CWE-89 | ✓ Exact Match |
| cwefixes/auth/controllers/group_controller.py | CWE-89 | ✓ Exact Match |
| cwefixes/auth/controllers/user_controller.py | CWE-89 | ✓ Exact Match |
| cwefixes/flair.py | CWE-89 | ✓ Exact Match |
| cwefixes/src/OFS/Image.py | CWE-79 | ✓ Exact Match |

### ⚠️ File con Rilevamento Parziale (Agent)

| File | CWE Vulnerabile | Rilevato | Falsi Positivi |
|------|-----------------|----------|----------------|
| cwefixes/app.py | CWE-89 | ✓ CWE-89 | CWE-285, CWE-489 |
| cwefixes/redports-trac/redports/model.py | CWE-89 | ✓ CWE-89 | CWE-20 |

### ❌ File Completamente Mancati (Agent)

- cwefixes/src/Products/PageTemplates/Expressions.py (CWE-22)
- cwefixes/src/Products/PageTemplates/expression.py (CWE-22)
- cwefixes/src/Products/PageTemplates/tests/testChameleonTalesExpressions.py (CWE-22)
- cwefixes/src/Products/PageTemplates/tests/testExpressions.py (CWE-22)
- cwefixes/src/Products/PageTemplates/tests/testHTMLTests.py (CWE-22)
- cwefixes/django/contrib/postgres/aggregates/general.py (CWE-89)
- cwefixes/django/contrib/postgres/aggregates/mixins.py (CWE-89)
- cwefixes/tests/postgres_tests/test_aggregates.py (CWE-89)
- cwefixes/tests/test_integration.py (CWE-89)
- cwefixes/src/Products/PageTemplates/ZRPythonExpr.py (CWE-79)
- cwefixes/src/Products/PageTemplates/tests/testZRPythonExpr.py (CWE-79)
- cwefixes/src/OFS/tests/testFileAndImage.py (CWE-79)
- cwefixes/reviewboard/reviews/templatetags/reviewtags.py (CWE-79)
- cwefixes/django/contrib/auth/tests/test_views.py (CWE-79)
- cwefixes/django/utils/http.py (CWE-79)
- cwefixes/django/contrib/admin/widgets.py (CWE-79)
- cwefixes/tests/admin_widgets/tests.py (CWE-79)

---

## 6. Punti Forti e Debolezze

### Agent

**✓ Punti Forti:**
- Precisione elevata (66.7%) - pochi falsi allarmi
- Buone prestazioni su CWE-89 (SQL Injection) con recall del 50%
- 6 identificazioni corrette esatte su 25 file (24%)

**✗ Debolezze:**
- Recall bassa (32%) - manca 2/3 delle vulnerabilità
- Problemi con CWE-22 (Path Traversal) e CWE-79 (XSS)
- Occasionali falsi positivi (4 su 8 rilevamenti TP)

### CodeQL

**✓ Punti Forti:**
- Nessun valore particolare; risultati molto inferiori a Agent

**✗ Debolezze:**
- Precision estremamente bassa (16.7%) - genera molti falsi allarmi
- Recall molto bassa (8%) - manca 92% delle vulnerabilità
- Completamente inefficace su CWE-79 (XSS)
- 23 false positives per ogni true positive rilevato

---

## 7. Raccomandazioni

### Per il Deployment

1. **Usare Agent come strumento principale** per il rilevamento di CWE, in particolare per CWE-89
2. **Non utilizzare CodeQL** per questa tipologia di analisi a meno di significativi miglioramenti
3. **Implementare un sistema di validazione manuale** dei risultati dell'Agent, soprattutto per i rilevamenti parziali

### Per il Miglioramento

1. **Agent - Migliorare la recall:**
   - Affinare il rilevamento per CWE-22 e CWE-79
   - Analizzare i 16 file mancati per identificare pattern comuni

2. **Ridurre i falsi positivi:**
   - Investigare i 4 falsi positivi generati
   - Implementare filtri post-processing

3. **CodeQL:**
   - Richiedere una rivalutazione o un retraining del modello
   - Considerare l'uso solo in combinazione con altri strumenti

---

## 8. Conclusioni

L'analisi mostra che **l'Agent personalizzato è significativamente superiore a CodeQL** nel rilevamento di vulnerabilità CWE, con un F1-Score di 43.2% contro 10.8%. Sebbene il recall possa essere migliorato, la precisione elevata dell'Agent lo rende un candidato valido per l'uso in ambienti di produzione, con appropriati meccanismi di verifica manuale.
