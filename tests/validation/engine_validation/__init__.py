"""Suite de validación del motor contra el dataset de referencia.

La lógica vive aquí, separada de los tests, para que el emparejamiento, las
métricas y los reportes tengan pruebas unitarias propias:

- discovery: encuentra los fixtures de vulnerable/, secure/ y real/.
- matching:  clasifica cada hallazgo como TP, FP o FN.
- metrics:   precision, recall y F1 globales y por categoría.
- runner:    ejecuta el motor sobre cada fixture.
- report:    genera validation-report.json y validation-report.md.
"""
