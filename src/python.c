/*
 * Copyright (c) 2025 Joris Vink <joris@sanctorum.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>

#define PY_SSIZE_T_CLEAN	1

#include <Python.h>

#include <libkyrka-int.h>
#include <stdarg.h>

#define CONSTANT(x)		{ #x, x, NULL }
#define METHOD(n, c, a)		{ n, (PyCFunction)c, a, NULL }

/*
 * Holds a pointer to a callable python object and a potential user-supplied
 * argument that is to be given to this callback. We use this for the internal
 * kyrka callbacks where required.
 */
struct callback {
	PyObject	*cb;
	PyObject	*arg;
};

/*
 * A wrapper around libkyrka its context and all required callbacks.
 * This is the data structure handed around in the python code.
 */
struct pykyrka {
	PyObject_HEAD

	KYRKA		*kyrka;

	struct callback	event;
	struct callback	heaven;
	struct callback	purgatory;
	struct callback	cathedral;
};

/*
 * Data structure to quickly map up integer constants to names for
 * providing them into the python code.
 */
struct integer {
	const char	*name;
	u_int64_t	value;
	PyObject	*obj;
};

PyMODINIT_FUNC		PyInit_libkyrka(void);
static void		python_fatal(const char *, va_list);

static PyObject		*pykyrka_alloc(PyObject *, PyObject *);
static PyObject		*pykyrka_version(PyObject *, PyObject *);
static PyObject		*pykyrka_key_manage(PyObject *, PyObject *);
static PyObject		*pykyrka_secret_load(PyObject *, PyObject *);
static PyObject		*pykyrka_encap_key_load(PyObject *, PyObject *);
static PyObject		*pykyrka_device_kek_load(PyObject *, PyObject *);
static PyObject		*pykyrka_secret_load_path(PyObject *, PyObject *);

static PyObject		*pykyrka_heaven_input(PyObject *, PyObject *);
static PyObject		*pykyrka_purgatory_input(PyObject *, PyObject *);

static PyObject		*pykyrka_cathedral_notify(PyObject *, PyObject *);
static PyObject		*pykyrka_cathedral_cosk_load(PyObject *, PyObject *);
static PyObject		*pykyrka_cathedral_secret_load(PyObject *, PyObject *);
static PyObject		*pykyrka_cathedral_nat_detection(PyObject *,
			    PyObject *);
static PyObject		*pykyrka_cathedral_configure(PyObject *,
			    PyObject *, PyObject *);

static PyObject		*pykyrka_event_callback(PyObject *, PyObject *);
static PyObject		*pykyrka_heaven_callback(PyObject *, PyObject *);
static PyObject		*pykyrka_purgatory_callback(PyObject *, PyObject *);

static void		python_kyrka_exception(u_int64_t);
static PyObject		*python_callback_set(PyObject *, struct callback *);
static void		python_callback_run(struct pykyrka *,
			    struct callback *, const void *, size_t, u_int64_t);

static PyObject		*python_integer_lookup(struct integer *, u_int64_t);
static int		python_integer_constants(PyObject *, struct integer *);

static const char	*python_string_from_dict(PyObject *, const char *);
static int		python_bool_from_dict(PyObject *, const char *, int *);

static int		python_dict_add_string(PyObject *,
			    const char *, const char *);
static int		python_dict_add_uint64(PyObject *,
			    const char *, u_int64_t);

static int		python_uint16_from_dict(PyObject *,
			    const char *, u_int16_t *);
static int		python_uint32_from_dict(PyObject *,
			    const char *, u_int32_t *);
static int		python_uint64_from_dict(PyObject *,
			    const char *, u_int64_t *);

static void	kyrka_cb_event(KYRKA *, union kyrka_event *, void *);
static void	kyrka_cb_heaven(const void *, size_t, u_int64_t, void *);
static void	kyrka_cb_cathedral(const void *, size_t, u_int64_t, void *);
static void	kyrka_cb_purgatory(const void *, size_t, u_int64_t, void *);

/*
 * The libkyrka context methods exposed to python.
 */
static PyMethodDef pykyrka_methods[] = {
	METHOD("key_manage", pykyrka_key_manage, METH_NOARGS),
	METHOD("secret_load", pykyrka_secret_load, METH_VARARGS),
	METHOD("heaven_input", pykyrka_heaven_input, METH_VARARGS),
	METHOD("event_callback", pykyrka_event_callback, METH_VARARGS),
	METHOD("encap_key_load", pykyrka_encap_key_load, METH_VARARGS),
	METHOD("device_kek_load", pykyrka_device_kek_load, METH_VARARGS),
	METHOD("purgatory_input", pykyrka_purgatory_input, METH_VARARGS),
	METHOD("heaven_callback", pykyrka_heaven_callback, METH_VARARGS),
	METHOD("cathedral_notify", pykyrka_cathedral_notify, METH_NOARGS),
	METHOD("secret_load_path", pykyrka_secret_load_path, METH_VARARGS),
	METHOD("purgatory_callback", pykyrka_purgatory_callback, METH_VARARGS),
	METHOD("cathedral_secret_load",
	    pykyrka_cathedral_secret_load, METH_VARARGS),
	METHOD("cathedral_cosk_load",
	    pykyrka_cathedral_cosk_load, METH_VARARGS),
	METHOD("cathedral_configure",
	    pykyrka_cathedral_configure, METH_VARARGS | METH_KEYWORDS),
	METHOD("cathedral_nat_detection", pykyrka_cathedral_nat_detection,
	    METH_NOARGS),
	{ NULL, NULL, 0, NULL },
};

/*
 * The python goo required to be able to create new pykyrka contexts
 * that wrap KYRKA ones.
 */
static void	pykyrka_dealloc(struct pykyrka *);

static PyTypeObject pykyrka_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "KYRKA",
	.tp_doc = "KYRKA context",
	.tp_methods = pykyrka_methods,
	.tp_basicsize = sizeof(struct pykyrka ),
	.tp_dealloc = (destructor)pykyrka_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE
};

/*
 * The methods provided at the top level of the libkyrka module.
 */
static PyMethodDef methods[] = {
	METHOD("alloc", pykyrka_alloc, METH_NOARGS),
	METHOD("version", pykyrka_version, METH_NOARGS),
	{ NULL, NULL, 0, NULL },
};

/*
 * The definition of the libkyrka module for instantiation in python.
 */
static PyModuleDef module = {
	PyModuleDef_HEAD_INIT, "libkyrka", NULL, 0, methods
};

/*
 * All integer constants for libkyrka events exposed to python.
 */
static struct integer constants_events[] = {
	CONSTANT(KYRKA_EVENT_KEYS_INFO),
	CONSTANT(KYRKA_EVENT_ENCAP_INFO),
	CONSTANT(KYRKA_EVENT_KEYS_ERASED),
	CONSTANT(KYRKA_EVENT_EXCHANGE_INFO),
	CONSTANT(KYRKA_EVENT_PEER_DISCOVERY),
	CONSTANT(KYRKA_EVENT_AMBRY_RECEIVED),
	CONSTANT(KYRKA_EVENT_LITURGY_RECEIVED),
	CONSTANT(KYRKA_EVENT_REMEMBRANCE_RECEIVED),
	{ NULL, -1, NULL },
};

/*
 * All integer constants for misc stuff exposed to python.
 */
static struct integer constants_misc[] = {
	CONSTANT(KYRKA_CATHEDRALS_MAX),
	CONSTANT(KYRKA_PEERS_PER_FLOCK),
	CONSTANT(KYRKA_CATHEDRAL_MAGIC),
	CONSTANT(KYRKA_CATHEDRAL_NAT_MAGIC),
	CONSTANT(KYRKA_CATHEDRAL_LITURGY_MAGIC),
	{ NULL, -1, NULL },
};

/*
 * All integer constants for error codes exposed to python.
 */
static struct integer constants_errors[] = {
	CONSTANT(KYRKA_ERROR_NONE),
	CONSTANT(KYRKA_ERROR_NO_KEK),
	CONSTANT(KYRKA_ERROR_SYSTEM),
	CONSTANT(KYRKA_ERROR_INTERNAL),
	CONSTANT(KYRKA_ERROR_PARAMETER),
	CONSTANT(KYRKA_ERROR_INTEGRITY),
	CONSTANT(KYRKA_ERROR_NO_TX_KEY),
	CONSTANT(KYRKA_ERROR_NO_RX_KEY),
	CONSTANT(KYRKA_ERROR_NO_SECRET),
	CONSTANT(KYRKA_ERROR_NO_CONFIG),
	CONSTANT(KYRKA_ERROR_FILE_ERROR),
	CONSTANT(KYRKA_ERROR_NO_CALLBACK),
	CONSTANT(KYRKA_ERROR_PACKET_ERROR),
	CONSTANT(KYRKA_ERROR_CATHEDRAL_CONFIG),
	{ NULL, -1, NULL },
};

/*
 * The module init function. This is called when the module is loaded.
 * We create a new module based on our definition earlier and populate
 * it with all required constants.
 */
PyMODINIT_FUNC
PyInit_libkyrka(void)
{
	PyObject	*mod;

	if ((mod = PyModule_Create(&module)) == NULL)
		return (NULL);

	if (python_integer_constants(mod, constants_misc) == -1 ||
	    python_integer_constants(mod, constants_errors) == -1 ||
	    python_integer_constants(mod, constants_events) == -1) {
		Py_DECREF(mod);
		return (NULL);
	}

	kyrka_fatal_callback(python_fatal);

	return (mod);
}

/*
 * Extremely bad juju happened, ideally we might not want our python
 * module to just blow up the entire process but we have no other choice.
 */
static void
python_fatal(const char *fmt, va_list args)
{
	kyrka_emergency_erase();

	fprintf(stderr, "fatal libkyrka error: ");
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");

	exit(1);
}

/*
 * Internal event callback for all allocated KYRKA contexts that based on the
 * event creates a python dict populated with relevant data.
 *
 * We then call into the python code.
 */
static void
kyrka_cb_event(KYRKA *kctx, union kyrka_event *evt, void *udata)
{
	struct pykyrka		*ctx;
	PyObject		*result, *event, *info;

	PRECOND(kctx != NULL);
	PRECOND(evt != NULL);
	PRECOND(udata != NULL);

	ctx = udata;

	if (ctx->event.cb == NULL)
		return;

	if ((info = PyDict_New()) == NULL)
		return;

	result = NULL;
	event = python_integer_lookup(constants_events, evt->type);

	switch (evt->type) {
	case KYRKA_EVENT_KEYS_INFO:
		if (python_dict_add_uint64(info, "tx", evt->keys.tx_spi) == -1)
			goto cleanup;
		if (python_dict_add_uint64(info, "rx", evt->keys.rx_spi) == -1)
			goto cleanup;
		break;
	case KYRKA_EVENT_KEYS_ERASED:
		if (python_dict_add_string(info, "reason", "keys erased") == -1)
			goto cleanup;
		break;
	case KYRKA_EVENT_LOGMSG:
		if (python_dict_add_string(info,
		    "logmsg", evt->logmsg.log) == -1)
			goto cleanup;
		break;
	case KYRKA_EVENT_EXCHANGE_INFO:
		if (python_dict_add_string(info,
		    "reason", evt->exchange.reason) == -1)
			goto cleanup;
		break;
	case KYRKA_EVENT_PEER_DISCOVERY:
		if (python_dict_add_uint64(info, "ip", evt->peer.ip) == -1)
			goto cleanup;
		if (python_dict_add_uint64(info, "port", evt->peer.port) == -1)
			goto cleanup;
		break;
	case KYRKA_EVENT_AMBRY_RECEIVED:
		if (python_dict_add_uint64(info,
		    "ambry", evt->ambry.generation) == -1)
			goto cleanup;
		break;
	case KYRKA_EVENT_LITURGY_RECEIVED:
		break;
	case KYRKA_EVENT_REMEMBRANCE_RECEIVED:
		break;
	case KYRKA_EVENT_ENCAP_INFO:
		if (python_dict_add_uint64(info, "spi", evt->encap.spi) == -1)
			goto cleanup;
		break;
	default:
		PyErr_Format(PyExc_RuntimeError,
		    "unknown libkyrka event %u", evt->type);
		goto cleanup;
	}

	result = PyObject_CallFunctionObjArgs(ctx->event.cb,
	    udata, event, info, ctx->event.arg, NULL);

cleanup:
	Py_DECREF(info);
	Py_XDECREF(result);
}

/*
 * Internal heaven callback for all KYRKA contexts allocated. We call
 * into the python provided heaven callback.
 */
static void
kyrka_cb_heaven(const void *data, size_t len, u_int64_t seq, void *udata)
{
	struct pykyrka		*ctx;

	PRECOND(data != NULL);
	PRECOND(len > 0);
	PRECOND(udata != NULL);

	ctx = (struct pykyrka *)udata;

	python_callback_run(udata, &ctx->heaven, data, len, seq);
}

/*
 * Internal purgatory callback for all KYRKA contexts allocated. We call
 * into the python provided purgatory callback.
 */
static void
kyrka_cb_purgatory(const void *data, size_t len, u_int64_t seq, void *udata)
{
	struct pykyrka		*ctx;

	PRECOND(data != NULL);
	PRECOND(len > 0);
	PRECOND(udata != NULL);

	ctx = (struct pykyrka *)udata;

	python_callback_run(udata, &ctx->purgatory, data, len, seq);
}

/*
 * Internal cathedral callback for all KYRKA contexts allocated. We call
 * into the python provided cathedral callback.
 */
static void
kyrka_cb_cathedral(const void *data, size_t len, u_int64_t magic, void *udata)
{
	struct pykyrka		*ctx;

	PRECOND(data != NULL);
	PRECOND(len > 0);
	PRECOND(udata != NULL);

	ctx = (struct pykyrka *)udata;

	python_callback_run(udata, &ctx->cathedral, data, len, magic);
}

/*
 * Entry from python for libkyrka.version().
 */
static PyObject *
pykyrka_version(PyObject *self, PyObject *args)
{
	PyObject	*version;

	PRECOND(self != NULL);
	PRECOND(args != NULL);

	if ((version = PyUnicode_FromString(kyrka_version())) == NULL)
		return (PyErr_NoMemory());

	return (version);
}

/*
 * Entry from python for libkyrka.alloc(). We create a new pykyrka
 * context and setup everything required before returning it to
 * the python code.
 */
static PyObject *
pykyrka_alloc(PyObject *self, PyObject *args)
{
	struct pykyrka		*ctx;

	PRECOND(self != NULL);

	if ((ctx = PyObject_New(struct pykyrka, &pykyrka_type)) == NULL)
		return (NULL);

	ctx->event.cb = NULL;
	ctx->heaven.cb = NULL;
	ctx->purgatory.cb = NULL;
	ctx->cathedral.cb = NULL;

	ctx->event.arg = NULL;
	ctx->heaven.arg = NULL;
	ctx->purgatory.arg = NULL;
	ctx->cathedral.arg = NULL;

	ctx->kyrka = kyrka_ctx_alloc(kyrka_cb_event, ctx);
	if (ctx->kyrka == NULL) {
		Py_DECREF(ctx);
		return (NULL);
	}

	if (kyrka_heaven_ifc(ctx->kyrka, kyrka_cb_heaven, ctx) == -1) {
		Py_DECREF(ctx);
		return (NULL);
	}

	if (kyrka_purgatory_ifc(ctx->kyrka, kyrka_cb_purgatory, ctx) == -1) {
		Py_DECREF(ctx);
		return (NULL);
	}

	return ((PyObject *)ctx);
}

/*
 * If all references go away we deallocate the pykyrka context.
 */
static void
pykyrka_dealloc(struct pykyrka *ctx)
{
	PRECOND(ctx != NULL);

	kyrka_ctx_free(ctx->kyrka);
	PyObject_Del((PyObject *)ctx);
}

/*
 * Entry from python for an allocated context key_manage().
 */
static PyObject *
pykyrka_key_manage(PyObject *self, PyObject *args)
{
	struct pykyrka		*ctx;

	PRECOND(self != NULL);

	ctx = (struct pykyrka *)self;

	if (kyrka_key_manage(ctx->kyrka) == -1) {
		python_kyrka_exception(kyrka_last_error(ctx->kyrka));
		return (NULL);
	}

	Py_RETURN_TRUE;
}

/*
 * Entry from python for an allocated context cathedral_notify().
 */
static PyObject *
pykyrka_cathedral_notify(PyObject *self, PyObject *args)
{
	struct pykyrka		*ctx;

	PRECOND(self != NULL);

	ctx = (struct pykyrka *)self;

	if (kyrka_cathedral_notify(ctx->kyrka) == -1) {
		python_kyrka_exception(kyrka_last_error(ctx->kyrka));
		return (NULL);
	}

	Py_RETURN_TRUE;
}

/*
 * Entry from python for an allocated context cathedral_nat_detection().
 */
static PyObject *
pykyrka_cathedral_nat_detection(PyObject *self, PyObject *args)
{
	struct pykyrka		*ctx;

	PRECOND(self != NULL);

	ctx = (struct pykyrka *)self;

	if (kyrka_cathedral_nat_detection(ctx->kyrka) == -1) {
		python_kyrka_exception(kyrka_last_error(ctx->kyrka));
		return (NULL);
	}

	Py_RETURN_TRUE;
}

/*
 * Entry from python for an allocated context secret_load().
 */
static PyObject *
pykyrka_secret_load(PyObject *self, PyObject *args)
{
	Py_buffer		buf;
	struct pykyrka		*ctx;

	PRECOND(self != NULL);
	PRECOND(args != NULL);

	if (!PyArg_ParseTuple(args, "y*", &buf))
		return (NULL);

	ctx = (struct pykyrka *)self;

	if (kyrka_secret_load(ctx->kyrka, buf.buf, buf.len) == -1) {
		PyBuffer_Release(&buf);
		python_kyrka_exception(kyrka_last_error(ctx->kyrka));
		return (NULL);
	}

	PyBuffer_Release(&buf);
	Py_RETURN_TRUE;
}

/*
 * Entry from python for an allocated context secret_load_path().
 */
static PyObject *
pykyrka_secret_load_path(PyObject *self, PyObject *args)
{
	struct pykyrka		*ctx;
	const char		*path;

	PRECOND(self != NULL);
	PRECOND(args != NULL);

	if (!PyArg_ParseTuple(args, "s", &path))
		return (NULL);

	ctx = (struct pykyrka *)self;

	if (kyrka_secret_load_path(ctx->kyrka, path) == -1) {
		python_kyrka_exception(kyrka_last_error(ctx->kyrka));
		return (NULL);
	}

	Py_RETURN_TRUE;
}

/*
 * Entry from python for an allocated context cathedral_cosk_load().
 */
static PyObject *
pykyrka_cathedral_cosk_load(PyObject *self, PyObject *args)
{
	Py_buffer		buf;
	struct pykyrka		*ctx;

	PRECOND(self != NULL);
	PRECOND(args != NULL);

	if (!PyArg_ParseTuple(args, "y*", &buf))
		return (NULL);

	ctx = (struct pykyrka *)self;

	if (kyrka_cathedral_cosk_load(ctx->kyrka, buf.buf, buf.len) == -1) {
		PyBuffer_Release(&buf);
		python_kyrka_exception(kyrka_last_error(ctx->kyrka));
		return (NULL);
	}

	PyBuffer_Release(&buf);
	Py_RETURN_TRUE;
}

/*
 * Entry from python for an allocated context cathedral_secret_load().
 */
static PyObject *
pykyrka_cathedral_secret_load(PyObject *self, PyObject *args)
{
	Py_buffer		buf;
	struct pykyrka		*ctx;

	PRECOND(self != NULL);
	PRECOND(args != NULL);

	if (!PyArg_ParseTuple(args, "y*", &buf))
		return (NULL);

	ctx = (struct pykyrka *)self;

	if (kyrka_cathedral_secret_load(ctx->kyrka, buf.buf, buf.len) == -1) {
		PyBuffer_Release(&buf);
		python_kyrka_exception(kyrka_last_error(ctx->kyrka));
		return (NULL);
	}

	PyBuffer_Release(&buf);
	Py_RETURN_TRUE;
}

/*
 * Entry from python for an allocated context device_kek_load().
 */
static PyObject *
pykyrka_device_kek_load(PyObject *self, PyObject *args)
{
	Py_buffer		buf;
	struct pykyrka		*ctx;

	PRECOND(self != NULL);
	PRECOND(args != NULL);

	if (!PyArg_ParseTuple(args, "y*", &buf))
		return (NULL);

	ctx = (struct pykyrka *)self;

	if (kyrka_device_kek_load(ctx->kyrka, buf.buf, buf.len) == -1) {
		PyBuffer_Release(&buf);
		python_kyrka_exception(kyrka_last_error(ctx->kyrka));
		return (NULL);
	}

	PyBuffer_Release(&buf);
	Py_RETURN_TRUE;
}

/*
 * Entry from python for an allocated context encap_key_load().
 */
static PyObject *
pykyrka_encap_key_load(PyObject *self, PyObject *args)
{
	Py_buffer		buf;
	struct pykyrka		*ctx;

	PRECOND(self != NULL);
	PRECOND(args != NULL);

	if (!PyArg_ParseTuple(args, "y*", &buf))
		return (NULL);

	ctx = (struct pykyrka *)self;

	if (kyrka_encap_key_load(ctx->kyrka, buf.buf, buf.len) == -1) {
		PyBuffer_Release(&buf);
		python_kyrka_exception(kyrka_last_error(ctx->kyrka));
		return (NULL);
	}

	PyBuffer_Release(&buf);
	Py_RETURN_TRUE;
}

/*
 * Entry from python for an allocated context heaven_input().
 */
static PyObject *
pykyrka_heaven_input(PyObject *self, PyObject *args)
{
	Py_buffer		buf;
	struct pykyrka		*ctx;

	PRECOND(self != NULL);
	PRECOND(args != NULL);

	if (!PyArg_ParseTuple(args, "y*", &buf))
		return (NULL);

	ctx = (struct pykyrka *)self;

	if (kyrka_heaven_input(ctx->kyrka, buf.buf, buf.len) == -1) {
		PyBuffer_Release(&buf);
		python_kyrka_exception(kyrka_last_error(ctx->kyrka));
		return (NULL);
	}

	PyBuffer_Release(&buf);
	Py_RETURN_TRUE;
}

/*
 * Entry from python for an allocated context purgatory_input().
 */
static PyObject *
pykyrka_purgatory_input(PyObject *self, PyObject *args)
{
	Py_buffer		buf;
	struct pykyrka		*ctx;

	PRECOND(self != NULL);
	PRECOND(args != NULL);

	if (!PyArg_ParseTuple(args, "y*", &buf))
		return (NULL);

	ctx = (struct pykyrka *)self;

	if (kyrka_purgatory_input(ctx->kyrka, buf.buf, buf.len) == -1) {
		PyBuffer_Release(&buf);
		python_kyrka_exception(kyrka_last_error(ctx->kyrka));
		return (NULL);
	}

	PyBuffer_Release(&buf);
	Py_RETURN_TRUE;
}

/*
 * Entry from python for an allocated context cathedral_config().
 *
 * This function from python takes a list of kwarg that match the
 * fields in the kyrka_cathedral_cfg data structure.
 */
static PyObject *
pykyrka_cathedral_configure(PyObject *self, PyObject *args, PyObject *kwargs)
{
	struct kyrka_cathedral_cfg	cfg;
	struct pykyrka			*ctx;

	PRECOND(self != NULL);
	PRECOND(args != NULL);

	if (kwargs == NULL) {
		PyErr_SetString(PyExc_RuntimeError, "missing keywords");
		return (NULL);
	}

	ctx = (struct pykyrka *)self;
	memset(&cfg, 0, sizeof(cfg));

	cfg.kek = python_string_from_dict(kwargs, "kek");
	cfg.cosk = python_string_from_dict(kwargs, "cosk");
	cfg.secret = python_string_from_dict(kwargs, "secret");

	if (python_uint64_from_dict(kwargs, "flock_src", &cfg.flock_src) == -1)
		return (NULL);

	if (python_uint64_from_dict(kwargs, "flock_dst", &cfg.flock_dst) == -1)
		return (NULL);

	if (python_uint32_from_dict(kwargs, "identity", &cfg.identity) == -1)
		return (NULL);

	if (python_uint16_from_dict(kwargs, "tunnel", &cfg.tunnel) == -1)
		return (NULL);

	if (python_uint16_from_dict(kwargs, "group", &cfg.group) == -1)
		return (NULL);

	if (python_bool_from_dict(kwargs, "hidden", &cfg.hidden) == -1)
		PyErr_Clear();

	if (python_bool_from_dict(kwargs,
	    "remembrance", &cfg.remembrance) == -1)
		PyErr_Clear();

	ctx->cathedral.cb = PyDict_GetItemString(kwargs, "send");
	if (ctx->cathedral.cb == NULL) {
		PyErr_Format(PyExc_RuntimeError, "missing send keyword");
		return (NULL);
	}

	if (!PyCallable_Check(ctx->cathedral.cb)) {
		PyErr_Format(PyExc_RuntimeError, "send argument not callable");
		return (NULL);
	}

	ctx->cathedral.arg = PyDict_GetItemString(kwargs, "udata");

	Py_INCREF(ctx->cathedral.cb);
	Py_XINCREF(ctx->cathedral.arg);

	cfg.udata = ctx;
	cfg.send = kyrka_cb_cathedral;

	if (kyrka_cathedral_config(ctx->kyrka, &cfg) == -1) {
		python_kyrka_exception(kyrka_last_error(ctx->kyrka));
		return (NULL);
	}

	Py_RETURN_NONE;
}

/*
 * Entry from python for an allocated context event_callback().
 */
static PyObject *
pykyrka_event_callback(PyObject *self, PyObject *args)
{
	struct pykyrka		*ctx;

	PRECOND(self != NULL);
	PRECOND(args != NULL);

	ctx = (struct pykyrka *)self;

	return (python_callback_set(args, &ctx->event));
}

/*
 * Entry from python for an allocated context heaven_callback().
 */
static PyObject *
pykyrka_heaven_callback(PyObject *self, PyObject *args)
{
	struct pykyrka		*ctx;

	PRECOND(self != NULL);
	PRECOND(args != NULL);

	ctx = (struct pykyrka *)self;

	return (python_callback_set(args, &ctx->heaven));
}

/*
 * Entry from python for an allocated context purgatory_callback().
 */
static PyObject *
pykyrka_purgatory_callback(PyObject *self, PyObject *args)
{
	struct pykyrka		*ctx;

	PRECOND(self != NULL);
	PRECOND(args != NULL);

	ctx = (struct pykyrka *)self;

	return (python_callback_set(args, &ctx->purgatory));
}

/*
 * Helper function to set the given callback to both python
 * objects that are given in args.
 * 
 * We take a reference to both.
 */
static PyObject *
python_callback_set(PyObject *args, struct callback *cb)
{
	PyObject	*obj, *arg;

	PRECOND(args != NULL);
	PRECOND(cb != NULL);

	if (!PyArg_ParseTuple(args, "OO", &obj, &arg))
		return (NULL);

	if (!PyCallable_Check(obj)) {
		PyErr_SetString(PyExc_RuntimeError, "object is a function");
		return (NULL);
	}

	Py_INCREF(obj);
	Py_XINCREF(arg);

	cb->cb = obj;
	cb->arg = arg;

	Py_RETURN_NONE;
}

/*
 * Helper function to run the given callback passing the rest of
 * the arguments to the python method.
 */
static void
python_callback_run(struct pykyrka *ctx, struct callback *cb,
    const void *data, size_t len, u_int64_t seqmag)
{
	PyObject	*result, *bytes, *obj;

	PRECOND(ctx != NULL);
	PRECOND(cb != NULL);
	PRECOND(data != NULL);
	PRECOND(len > 0);

	if (cb->cb == NULL)
		return;

	if ((bytes = PyBytes_FromStringAndSize(data, len)) == NULL)
		return;

	if ((obj = PyLong_FromUnsignedLongLong(seqmag)) == NULL) {
		Py_DECREF(bytes);
		return;
	}

	result = PyObject_CallFunctionObjArgs(cb->cb,
	    ctx, bytes, obj, cb->arg, NULL);

	Py_DECREF(obj);
	Py_DECREF(bytes);
	Py_XDECREF(result);
}

/*
 * Helper function to obtain an uint16 from a dict, with range checking.
 */
static int
python_uint16_from_dict(PyObject *dict, const char *key, u_int16_t *val)
{
	u_int64_t		result;

	PRECOND(dict != NULL);
	PRECOND(key != NULL);
	PRECOND(val != NULL);

	if (python_uint64_from_dict(dict, key, &result) == -1)
		return (-1);

	if (result > USHRT_MAX) {
		PyErr_Format(PyExc_RuntimeError,
		    "integer 0x%" PRIx64 "out of range for uint16", result);
		return (-1);
	}

	*val = result;

	return (0);
}

/*
 * Helper function to obtain an uint32 from a dict, with range checking.
 */
static int
python_uint32_from_dict(PyObject *dict, const char *key, u_int32_t *val)
{
	u_int64_t		result;

	PRECOND(dict != NULL);
	PRECOND(key != NULL);
	PRECOND(val != NULL);

	if (python_uint64_from_dict(dict, key, &result) == -1)
		return (-1);

	if (result > UINT_MAX) {
		PyErr_Format(PyExc_RuntimeError,
		    "integer 0x%" PRIx64 "out of range for uint32", result);
		return (-1);
	}

	*val = result;

	return (0);
}

/*
 * Helper function to obtain an uint64 from a dict, with range checking.
 */
static int
python_uint64_from_dict(PyObject *dict, const char *key, u_int64_t *val)
{
	PyObject		*obj;
	unsigned long long	result;

	PRECOND(dict != NULL);
	PRECOND(key != NULL);
	PRECOND(val != NULL);

	if ((obj = PyDict_GetItemString(dict, key)) == NULL) {
		PyErr_Format(PyExc_RuntimeError, "missing integer '%s'", key);
		return (-1);
	}

	if (!PyLong_CheckExact(obj)) {
		PyErr_Format(PyExc_RuntimeError, "'%s' not an integer", key);
		return (-1);
	}

	PyErr_Clear();
	result = PyLong_AsUnsignedLongLong(obj);
	if (result == (unsigned long long)-1 && PyErr_Occurred()) {
		PyErr_Clear();
		PyErr_Format(PyExc_RuntimeError, "invalid integer '%s'", key);
		return (-1);
	}

	*val = result;

	return (0);
}

/*
 * Helper function to obtain an boolean from a dict.
 */
static int
python_bool_from_dict(PyObject *dict, const char *key, int *result)
{
	PyObject	*obj;

	PRECOND(dict != NULL);
	PRECOND(key != NULL);
	PRECOND(result != NULL);

	if ((obj = PyDict_GetItemString(dict, key)) == NULL) {
		PyErr_Format(PyExc_RuntimeError, "missing boolean '%s'", key);
		return (-1);
	}

	if (!PyBool_Check(obj)) {
		PyErr_Format(PyExc_RuntimeError, "'%s' not an boolean", key);
		return (-1);
	}

	*result = (obj == Py_True);

	return (0);
}

/*
 * Helper function to obtain a string from a dict.
 */
static const char *
python_string_from_dict(PyObject *dict, const char *key)
{
	PyObject	*obj;

	PRECOND(dict != NULL);
	PRECOND(key != NULL);

	if ((obj = PyDict_GetItemString(dict, key)) == NULL) {
		PyErr_Format(PyExc_RuntimeError, "missing string '%s'", key);
		return (NULL);
	}

	if (!PyUnicode_Check(obj)) {
		PyErr_Format(PyExc_RuntimeError, "'%s' not a string", key);
		return (NULL);
	}

	return (PyUnicode_AsUTF8AndSize(obj, NULL));
}

/*
 * Helper function to add a string to a dict under the given key.
 */
static int
python_dict_add_string(PyObject *dict, const char *name, const char *value)
{
	PyObject	*obj;

	PRECOND(dict != NULL);
	PRECOND(name != NULL);
	PRECOND(value != NULL);

	if ((obj = PyUnicode_FromString(value)) == NULL)
		return (-1);

	if (PyDict_SetItemString(dict, name, obj) == -1) {
		Py_DECREF(obj);
		return (-1);
	}

	return (0);
}

/*
 * Helper function to add a uint64 to a dict under the given key.
 */
static int
python_dict_add_uint64(PyObject *dict, const char *name, u_int64_t value)
{
	PyObject	*obj;

	PRECOND(dict != NULL);
	PRECOND(name != NULL);

	if ((obj = PyLong_FromUnsignedLongLong(value)) == NULL)
		return (-1);

	if (PyDict_SetItemString(dict, name, obj) == -1) {
		Py_DECREF(obj);
		return (-1);
	}

	return (0);
}

/*
 * Helper function to push a constant uint64 value into the module
 * so it can be accessed from python.
 */
static int
python_integer_constants(PyObject *mod, struct integer *list)
{
	int		i;

	PRECOND(mod != NULL);
	PRECOND(list != NULL);

	for (i = 0; list[i].name != NULL; i++) {
		list[i].obj = PyLong_FromUnsignedLongLong(list[i].value);
		if (list[i].obj == NULL) {
			PyErr_Format(PyExc_RuntimeError,
			    "failed to create %s", list[i].name);
			return (-1);
		}

		if (PyModule_AddObject(mod, list[i].name, list[i].obj) == -1) {
			PyErr_Format(PyExc_RuntimeError,
			    "failed to register %s", list[i].name);
			return (-1);
		}
	}

	return (0);
}

/*
 * Helper function to lookup a given integer object with the given
 * value from the list provided.
 */
static PyObject *
python_integer_lookup(struct integer *list, u_int64_t value)
{
	int		i;

	PRECOND(list != NULL);

	for (i = 0; list[i].name != NULL; i++) {
		if (list[i].value == value)
			return (list[i].obj);
	}

	Py_RETURN_NONE;
}

/*
 * Helper function that makes sure that a RuntimeError exception
 * is set based on the given libkyrka error.
 */
static void
python_kyrka_exception(u_int64_t error)
{
	int		i;

	for (i = 0; constants_errors[i].name != NULL; i++) {
		if (constants_errors[i].value == error)
			break;
	}

	if (constants_errors[i].name == NULL) {
		PyErr_Format(PyExc_RuntimeError, "error '%d' not found", error);
	} else {
		PyErr_SetObject(PyExc_RuntimeError, constants_errors[i].obj);
	}
}
