#define FP_COMPONENT "goodix55a2"

#include "drivers_api.h"

#include "fpi-byte-utils.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ctype.h>
#include <string.h>

#define GOODIX55A2_EP_OUT   (0x01 | FPI_USB_ENDPOINT_OUT)
#define GOODIX55A2_EP_IN    (0x02 | FPI_USB_ENDPOINT_IN)

#define GOODIX55A2_SENSOR_WIDTH   56
#define GOODIX55A2_SENSOR_HEIGHT  176

#define GOODIX55A2_FRAME_WIDTH    GOODIX55A2_SENSOR_HEIGHT
#define GOODIX55A2_FRAME_HEIGHT   GOODIX55A2_SENSOR_WIDTH

#define GOODIX55A2_DPI 500.0
#define GOODIX55A2_PPMM (GOODIX55A2_DPI / 25.4)   // ~19.685

#define GOODIX55A2_FRAME_PIXELS   (GOODIX55A2_SENSOR_WIDTH * GOODIX55A2_SENSOR_HEIGHT)
#define GOODIX55A2_PACKED_FRAME   ((GOODIX55A2_FRAME_PIXELS * 12) / 8)
#define GOODIX55A2_FRAME_CHECKSUM 4

#define GOODIX55A2_CMD_TIMEOUT    10000
#define GOODIX55A2_ACK_TIMEOUT    10000
#define GOODIX55A2_TLS_TIMEOUT    1000

#define GOODIX55A2_MAX_TRANSFER   32768

typedef enum
{
  GOODIX55A2_REPLY_FLAG_NONE = 0,
  GOODIX55A2_REPLY_FLAG_OPTIONAL_TAIL = 1 << 0,
} Goodix55A2ReplyFlags;

static const guint8 goodix55a2_expected_fw[] = "GF3206_RTSEC_APP_10056";

static const guint8 goodix55a2_psk[32] = { 0 };

static const guint8 goodix55a2_pmk_hash[] = {
  0x81, 0xb8, 0xff, 0x49, 0x06, 0x12, 0x02, 0x2a,
  0x12, 0x1a, 0x94, 0x49, 0xee, 0x3a, 0xad, 0x27,
  0x92, 0xf3, 0x2b, 0x9f, 0x31, 0x41, 0x18, 0x2c,
  0xd0, 0x10, 0x19, 0x94, 0x5e, 0xe5, 0x03, 0x61
};

static const guint8 goodix55a2_psk_wb[] = {
  0xec, 0x35, 0xae, 0x3a, 0xbb, 0x45, 0xed, 0x3f,
  0x12, 0xc4, 0x75, 0x1f, 0x1e, 0x5c, 0x2c, 0xc0,
  0x5b, 0x3c, 0x54, 0x52, 0xe9, 0x10, 0x4d, 0x9f,
  0x2a, 0x31, 0x18, 0x64, 0x4f, 0x37, 0xa0, 0x4b,
  0x6f, 0xd6, 0x6b, 0x1d, 0x97, 0xcf, 0x80, 0xf1,
  0x34, 0x5f, 0x76, 0xc8, 0x4f, 0x03, 0xff, 0x30,
  0xbb, 0x51, 0xbf, 0x30, 0x8f, 0x2a, 0x98, 0x75,
  0xc4, 0x1e, 0x65, 0x92, 0xcd, 0x2a, 0x2f, 0x9e,
  0x60, 0x80, 0x9b, 0x17, 0xb5, 0x31, 0x60, 0x37,
  0xb6, 0x9b, 0xb2, 0xfa, 0x5d, 0x4c, 0x8a, 0xc3,
  0x1e, 0xdb, 0x33, 0x94, 0x04, 0x6e, 0xc0, 0x6b,
  0xbd, 0xac, 0xc5, 0x7d, 0xa6, 0xa7, 0x56, 0xc5
};

static const char goodix55a2_chip_config_hex[] =
  "301160712c9d2cc91ce518fd00fd00fd03ba000080ca0006008400"
  "beb28600c5b98800b5ad8a009d958c0000be8e0000c5900000b592"
  "00009d940000af960000bf980000b69a0000a7d2000000d4000000"
  "d6000000d800000012000304d00000007000000072007856740034"
  "12200010402a0102002200012024003200800001045c0000015600"
  "30485800020032000802660000027c000038820080152a01820322"
  "00012024001400800001045c00000156000c245800050032000802"
  "660000027c000038820080162a0108005c00800054000001620038"
  "0464001000660000027c0001382a0108005c000001520008005400"
  "0001660000027c00013800e858";

static const char goodix55a2_fdt_mode_hex[] =
  "0d0180a08093809b80948090808f8094808b808a8083";

static const char goodix55a2_wait_finger_hex[] =
  "0c0180b980b480b580af80b480ac80b280a780ab80a5";


struct _FpiDeviceGoodix55a2
{
  FpImageDevice parent;

  gboolean      opened;
  gboolean      active;

  SSL_CTX      *ssl_ctx;
  SSL          *ssl;
  BIO          *rbio;
  BIO          *wbio;
  gboolean      tls_ready;
};

G_DECLARE_FINAL_TYPE (FpiDeviceGoodix55a2, fpi_device_goodix55a2, FPI, DEVICE_GOODIX55A2, FpImageDevice)
G_DEFINE_TYPE (FpiDeviceGoodix55a2, fpi_device_goodix55a2, FP_TYPE_IMAGE_DEVICE)

static inline guint
goodix55a2_sum (const guint8 *data,
                gsize         len)
{
  guint sum = 0;

  for (gsize i = 0; i < len; i++)
    sum += data[i];

  return sum & 0xff;
}

static void
goodix55a2_pad64 (GByteArray *array)
{
  gsize padding;

  if (!array)
    return;

  padding = 64 - (array->len % 64);
  if (padding == 64)
    return;

  g_byte_array_set_size (array, array->len + padding);
  memset (array->data + array->len - padding, 0, padding);
}

static GByteArray *
goodix55a2_bytes_from_hex (const char *hex)
{
  GByteArray *bytes;
  guint8 high = 0;
  gboolean have_high = FALSE;

  bytes = g_byte_array_new ();

  for (const char *c = hex; *c; c++)
    {
      if (g_ascii_isspace (*c))
        continue;

      if (!isxdigit (*c))
        continue;

      guint8 value = (guint8) g_ascii_xdigit_value (*c);

      if (!have_high)
        {
          high = value << 4;
          have_high = TRUE;
        }
      else
        {
          guint8 byte = high | value;
          g_byte_array_append (bytes, &byte, 1);
          have_high = FALSE;
        }
    }

  if (have_high)
    {
      guint8 byte = high;
      g_byte_array_append (bytes, &byte, 1);
    }

  return bytes;
}
static void
goodix55a2_detrend_columns_u8 (guint8 *img, int w, int h)
{
  // we calculate the mean of each column, and subtract the column bias relative to the global mean
  g_autofree int *col_mean = g_new0 (int, w);

  long global_sum = 0;
  for (int x = 0; x < w; x++)
    {
      long s = 0;
      for (int y = 0; y < h; y++)
        s += img[y * w + x];
      col_mean[x] = (int) (s / h);
      global_sum += col_mean[x];
    }

  int global_mean = (int) (global_sum / w);

  for (int x = 0; x < w; x++)
    {
      int bias = col_mean[x] - global_mean;
      for (int y = 0; y < h; y++)
        {
          int v = (int) img[y * w + x] - bias;
          if (v < 0) v = 0;
          if (v > 255) v = 255;   // [0,255]
          img[y * w + x] = (guint8) v;
        }
    }
}

static gboolean
goodix55a2_usb_bulk_write (FpiDeviceGoodix55a2 *self,
                           const guint8        *data,
                           gsize                len,
                           guint                timeout,
                           GError             **error)
{
  gsize offset = 0;

  while (offset < len)
    {
      gsize chunk = MIN (len - offset, 64);
      FpiUsbTransfer *transfer = fpi_usb_transfer_new (FP_DEVICE (self));

      fpi_usb_transfer_fill_bulk_full (transfer,
                                       GOODIX55A2_EP_OUT,
                                       g_memdup2 (data + offset, chunk),
                                       chunk,
                                       g_free);
      transfer->short_is_error = TRUE;

      if (!fpi_usb_transfer_submit_sync (transfer, timeout, error))
        {
          fpi_usb_transfer_unref (transfer);
          return FALSE;
        }

      offset += chunk;
      fpi_usb_transfer_unref (transfer);
    }

  return TRUE;
}

static gboolean
goodix55a2_usb_bulk_read (FpiDeviceGoodix55a2 *self,
                          GByteArray         **reply,
                          guint                timeout,
                          GError             **error)
{
  GByteArray *array;
  FpiUsbTransfer *transfer;

  transfer = fpi_usb_transfer_new (FP_DEVICE (self));
  transfer->short_is_error = FALSE;
  fpi_usb_transfer_fill_bulk (transfer, GOODIX55A2_EP_IN, GOODIX55A2_MAX_TRANSFER);

  if (!fpi_usb_transfer_submit_sync (transfer, timeout, error))
    {
      fpi_usb_transfer_unref (transfer);
      return FALSE;
    }

  array = g_byte_array_sized_new (transfer->actual_length);
  g_byte_array_append (array, transfer->buffer, transfer->actual_length);

  fpi_usb_transfer_unref (transfer);

  *reply = array;
  return TRUE;
}

static GByteArray *
goodix55a2_build_command (guint8        cmd,
                          const guint8 *payload,
                          gsize         payload_len)
{
  GByteArray *inner;
  GByteArray *complete;
  guint8 header[3];
  guint8 checksum;

  inner = g_byte_array_sized_new (payload_len + 4);
  g_byte_array_append (inner, &cmd, 1);

  guint16 len_field = payload_len + 1;
  guint8 len_bytes[2] = { len_field & 0xff, (len_field >> 8) & 0xff };
  g_byte_array_append (inner, len_bytes, 2);

  if (payload_len)
    g_byte_array_append (inner, payload, payload_len);

  checksum = (0xaa - goodix55a2_sum (inner->data, inner->len)) & 0xff;
  g_byte_array_append (inner, &checksum, 1);

  header[0] = 0xa0;
  guint16 total_len = inner->len;
  header[1] = total_len & 0xff;
  header[2] = (total_len >> 8) & 0xff;

  complete = g_byte_array_sized_new (inner->len + 3);
  g_byte_array_append (complete, header, 3);

  guint8 usb_checksum = goodix55a2_sum (complete->data, complete->len);
  g_byte_array_append (complete, &usb_checksum, 1);
  g_byte_array_append (complete, inner->data, inner->len);

  g_byte_array_unref (inner);

  goodix55a2_pad64 (complete);
  return complete;
}

static GByteArray *
goodix55a2_build_tls (const guint8 *payload,
                      gsize         payload_len)
{
  guint8 header[3];
  GByteArray *array;

  header[0] = 0xb0;
  header[1] = payload_len & 0xff;
  header[2] = (payload_len >> 8) & 0xff;
  guint8 checksum = goodix55a2_sum (header, 3);

  array = g_byte_array_sized_new (payload_len + 4);
  g_byte_array_append (array, header, 3);
  g_byte_array_append (array, &checksum, 1);
  if (payload_len)
    g_byte_array_append (array, payload, payload_len);

  goodix55a2_pad64 (array);
  return array;
}

static gboolean
goodix55a2_send_command_full (FpiDeviceGoodix55a2 *self,
                              guint8               cmd,
                              const guint8        *payload,
                              gsize                payload_len,
                              guint                reply_count,
                              Goodix55A2ReplyFlags flags,
                              GPtrArray          **out_replies,
                              GError             **error)
{
  g_autoptr(GByteArray) packet = NULL;
  GPtrArray *responses = NULL;

  packet = goodix55a2_build_command (cmd, payload, payload_len);
  if (!goodix55a2_usb_bulk_write (self, packet->data, packet->len, GOODIX55A2_CMD_TIMEOUT, error))
    return FALSE;

  responses = g_ptr_array_new_with_free_func ((GDestroyNotify) g_byte_array_unref);

  for (guint i = 0; i < reply_count; i++)
    {
      GByteArray *reply = NULL;

      g_autoptr(GError) read_error = NULL;

      if (!goodix55a2_usb_bulk_read (self, &reply, GOODIX55A2_ACK_TIMEOUT, &read_error))
        {
          if ((flags & GOODIX55A2_REPLY_FLAG_OPTIONAL_TAIL) &&
              responses->len > 0 &&
              g_error_matches (read_error,
                               G_USB_DEVICE_ERROR,
                               G_USB_DEVICE_ERROR_TIMED_OUT))
            {
              fp_dbg ("Command 0x%02x: timeout waiting for optional reply %u/%u",
                      cmd, i + 1, reply_count);
              break;
            }

          g_propagate_error (error, g_steal_pointer (&read_error));
          g_ptr_array_unref (responses);
          return FALSE;
        }

      g_ptr_array_add (responses, reply);
    }

  if (out_replies)
    *out_replies = responses;
  else
    g_ptr_array_unref (responses);

  return TRUE;
}

static gboolean
goodix55a2_send_command (FpiDeviceGoodix55a2 *self,
                         guint8               cmd,
                         const guint8        *payload,
                         gsize                payload_len,
                         guint                reply_count,
                         GPtrArray          **out_replies,
                         GError             **error)
{
  return goodix55a2_send_command_full (self,
                                       cmd,
                                       payload,
                                       payload_len,
                                       reply_count,
                                       GOODIX55A2_REPLY_FLAG_NONE,
                                       out_replies,
                                       error);
}

static gboolean
goodix55a2_send_tls (FpiDeviceGoodix55a2 *self,
                     const guint8        *payload,
                     gsize                payload_len,
                     guint                reply_count,
                     GPtrArray          **out_replies,
                     GError             **error)
{
  g_autoptr(GByteArray) packet = NULL;
  GPtrArray *responses = NULL;

  packet = goodix55a2_build_tls (payload, payload_len);
  if (!goodix55a2_usb_bulk_write (self, packet->data, packet->len, GOODIX55A2_TLS_TIMEOUT, error))
    return FALSE;

  responses = g_ptr_array_new_with_free_func ((GDestroyNotify) g_byte_array_unref);
  for (guint i = 0; i < reply_count; i++)
    {
      GByteArray *reply = NULL;

      if (!goodix55a2_usb_bulk_read (self, &reply, GOODIX55A2_TLS_TIMEOUT, error))
        {
          g_ptr_array_unref (responses);
          return FALSE;
        }

      g_ptr_array_add (responses, reply);
    }

  if (out_replies)
    *out_replies = responses;
  else
    g_ptr_array_unref (responses);

  return TRUE;
}

static gboolean
goodix55a2_extract_payload (GByteArray     *packet,
                            const guint8  **payload,
                            gsize          *payload_len,
                            GError        **error)
{
  guint8 type;
  gsize header_len;

  if (!packet || packet->len < 4)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                   "Goodix TLS packet too short");
      return FALSE;
    }

  type = packet->data[0];
  switch (type)
    {
    case 0xb0:
      header_len = 4;
      break;
    case 0xb2:
      header_len = 13;
      break;
    default:
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                   "Unexpected TLS container type 0x%02x", type);
      return FALSE;
    }

  if (packet->len < header_len)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                   "Malformed TLS container (len %u header %u)", packet->len, (guint) header_len);
      return FALSE;
    }

  *payload = packet->data + header_len;
  *payload_len = packet->len - header_len;
  return TRUE;
}

static gboolean
goodix55a2_check_firmware (FpiDeviceGoodix55a2 *self,
                           GError             **error)
{
  static const guint8 request[] = { 0x00, 0x00 };
  g_autoptr(GPtrArray) replies = NULL;

  if (!goodix55a2_send_command (self, 0xa8, request, sizeof (request), 2, &replies, error))
    return FALSE;

  if (replies->len < 2)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                   "Firmware response missing payload");
      return FALSE;
    }

  GByteArray *payload = g_ptr_array_index (replies, 1);
  if (payload->len < 8)
    return TRUE;

  gsize fw_len = payload->len - 8;
  if (fw_len != sizeof (goodix55a2_expected_fw))
    {
      fp_warn ("Unexpected firmware info length: %u", (guint) fw_len);
      return TRUE;
    }

  if (memcmp (payload->data + 7, goodix55a2_expected_fw, fw_len) != 0)
    fp_warn ("Unexpected firmware reported by Goodix sensor");
  else
    fp_dbg ("Goodix firmware validated");

  return TRUE;
}

static gboolean
goodix55a2_update_psk (FpiDeviceGoodix55a2 *self,
                       GError             **error)
{
  static const guint8 query[] = { 0x07, 0x00, 0x02, 0xbb, 0x00, 0x00, 0x00, 0x00 };
  g_autoptr(GPtrArray) replies = NULL;
  gboolean match = FALSE;

  if (!goodix55a2_send_command (self, 0xe4, query, sizeof (query), 2, &replies, error))
    return FALSE;

  if (replies->len < 2)
    return TRUE;

  GByteArray *frame = g_ptr_array_index (replies, replies->len - 1);
  if (frame->len > 17)
    {
      gsize pmk_len = frame->len - 17;
      const guint8 *pmk = frame->data + 16;

      if (pmk_len == sizeof (goodix55a2_pmk_hash) &&
          memcmp (pmk, goodix55a2_pmk_hash, pmk_len) == 0)
        match = TRUE;
    }

  if (match)
    {
      fp_dbg ("Goodix PSK already provisioned");
      return TRUE;
    }

  fp_dbg ("Updating Goodix PSK");

  g_autoptr(GByteArray) psk_id = goodix55a2_bytes_from_hex (
      "020001bb0e0000004141414142424242434343434444");
  if (!goodix55a2_send_command (self, 0xe0, psk_id->data, psk_id->len, 2, NULL, error))
    return FALSE;

  g_autoptr(GByteArray) psk_payload = goodix55a2_bytes_from_hex ("030001bb60000000");
  g_byte_array_append (psk_payload, goodix55a2_psk_wb, sizeof (goodix55a2_psk_wb));

  if (!goodix55a2_send_command (self, 0xe0, psk_payload->data, psk_payload->len, 2, NULL, error))
    return FALSE;

  return TRUE;
}

static gboolean
goodix55a2_initial_spi (FpiDeviceGoodix55a2 *self,
                        GError             **error)
{
  g_autoptr(GByteArray) chip_cfg = NULL;
  g_autoptr(GByteArray) fdt_cfg = NULL;
  static const guint8 reset[] = { 0x05, 0x14 };
  static const guint8 read_reg[] = { 0x00, 0x00, 0x00, 0x04, 0x00 };
  static const guint8 zero4[] = { 0x00, 0x00, 0x00, 0x00 };
  static const guint8 zero2[] = { 0x00, 0x00 };
  static const guint8 drv_state[] = { 0x01, 0x00 };

  chip_cfg = goodix55a2_bytes_from_hex (goodix55a2_chip_config_hex);
  fdt_cfg = goodix55a2_bytes_from_hex (goodix55a2_fdt_mode_hex);

  if (!goodix55a2_send_command (self, 0xa2, reset, sizeof (reset), 2, NULL, error) ||
      !goodix55a2_send_command (self, 0x82, read_reg, sizeof (read_reg), 2, NULL, error) ||
      !goodix55a2_send_command (self, 0x00, zero4, sizeof (zero4), 1, NULL, error) ||
      !goodix55a2_send_command (self, 0xa6, zero2, sizeof (zero2), 2, NULL, error) ||
      !goodix55a2_send_command (self, 0xd6, zero2, sizeof (zero2), 2, NULL, error) ||
      !goodix55a2_send_command (self, 0x90, chip_cfg->data, chip_cfg->len, 2, NULL, error) ||
      !goodix55a2_send_command (self, 0xc4, drv_state, sizeof (drv_state), 1, NULL, error) ||
      !goodix55a2_send_command (self, 0xd2, zero2, sizeof (zero2), 2, NULL, error) ||
      !goodix55a2_send_command_full (self,
                                     0x36,
                                     fdt_cfg->data,
                                     fdt_cfg->len,
                                     2,
                                     GOODIX55A2_REPLY_FLAG_OPTIONAL_TAIL,
                                     NULL,
                                     error))
    return FALSE;

  return TRUE;
}

static gboolean
goodix55a2_request_finger_detection (FpiDeviceGoodix55a2 *self,
                                     GError             **error)
{
  g_autoptr(GByteArray) wait_cfg = goodix55a2_bytes_from_hex (goodix55a2_wait_finger_hex);

  return goodix55a2_send_command (self, 0x32, wait_cfg->data, wait_cfg->len, 2, NULL, error);
}

static unsigned int
goodix55a2_psk_callback (SSL         *ssl,
                         const char  *identity,
                         unsigned char *psk,
                         unsigned int  max_psk_len)
{
  if (max_psk_len < sizeof (goodix55a2_psk))
    return 0;

  memcpy (psk, goodix55a2_psk, sizeof (goodix55a2_psk));
  return sizeof (goodix55a2_psk);
}

static gboolean
goodix55a2_tls_prepare (FpiDeviceGoodix55a2 *self,
                        GError             **error)
{
  if (self->ssl)
    return TRUE;

  self->ssl_ctx = SSL_CTX_new (TLS_server_method ());
  if (!self->ssl_ctx)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                   "Unable to create TLS context: %s", ERR_error_string (ERR_get_error (), NULL));
      return FALSE;
    }

  SSL_CTX_set_psk_server_callback (self->ssl_ctx, goodix55a2_psk_callback);
  SSL_CTX_set_min_proto_version (self->ssl_ctx, TLS1_VERSION);
  SSL_CTX_set_max_proto_version (self->ssl_ctx, TLS1_2_VERSION);
  if (SSL_CTX_set_cipher_list (self->ssl_ctx,
                               "PSK-AES128-CBC-SHA256:PSK-AES256-CBC-SHA:PSK-AES128-CBC-SHA") != 1)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                   "Unable to configure TLS ciphers");
      return FALSE;
    }

  self->ssl = SSL_new (self->ssl_ctx);
  if (!self->ssl)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                   "Unable to allocate TLS session: %s", ERR_error_string (ERR_get_error (), NULL));
      return FALSE;
    }

  SSL_set_accept_state (self->ssl);
  BIO *rbio = BIO_new (BIO_s_mem ());
  BIO *wbio = BIO_new (BIO_s_mem ());
  SSL_set_bio (self->ssl, rbio, wbio);
  self->rbio = SSL_get_rbio (self->ssl);
  self->wbio = SSL_get_wbio (self->ssl);

  return TRUE;
}

static gboolean
goodix55a2_tls_flush (FpiDeviceGoodix55a2 *self,
                      guint                expected_replies,
                      GPtrArray          **out_replies,
                      GError             **error)
{
  gssize pending;
  g_autofree guint8 *buffer = NULL;

  pending = BIO_ctrl_pending (self->wbio);
  if (pending <= 0)
    {
      if (expected_replies && out_replies)
        *out_replies = NULL;
      return TRUE;
    }

  buffer = g_malloc (pending);
  gssize read = BIO_read (self->wbio, buffer, pending);
  if (read <= 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                   "Failed to read TLS payload");
      return FALSE;
    }

  return goodix55a2_send_tls (self, buffer, read, expected_replies, out_replies, error);
}

static gboolean
goodix55a2_tls_feed (FpiDeviceGoodix55a2 *self,
                     const guint8        *payload,
                     gsize                payload_len,
                     GError             **error)
{
  if (BIO_write (self->rbio, payload, payload_len) != (gssize) payload_len)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                   "Failed to feed TLS payload");
      return FALSE;
    }

  int ret = SSL_do_handshake (self->ssl);
  if (ret == 1)
    {
      self->tls_ready = TRUE;
      return TRUE;
    }

  int ssl_err = SSL_get_error (self->ssl, ret);
  if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)
    return TRUE;

  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
               "TLS handshake failed (%d)", ssl_err);
  return FALSE;
}

static gboolean
goodix55a2_tls_handshake (FpiDeviceGoodix55a2 *self,
                          GError             **error)
{
  static const guint8 zero2[] = { 0x00, 0x00 };
  g_autoptr(GPtrArray) replies = NULL;

  if (self->tls_ready)
    return TRUE;

  if (!goodix55a2_tls_prepare (self, error))
    return FALSE;

  static const guint8 zero4[] = { 0x00, 0x00, 0x00, 0x00 };

  if (!goodix55a2_send_command (self, 0x00, zero4, sizeof (zero4), 1, NULL, error) ||
      !goodix55a2_send_command (self, 0xd0, zero2, sizeof (zero2), 2, &replies, error))
    return FALSE;

  if (replies->len < 2)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                   "TLS negotiation missing client hello");
      return FALSE;
    }

  GByteArray *client_frame = g_ptr_array_index (replies, replies->len - 1);
  const guint8 *client_payload = NULL;
  gsize client_len = 0;
  if (!goodix55a2_extract_payload (client_frame, &client_payload, &client_len, error))
    return FALSE;

  if (!goodix55a2_tls_feed (self, client_payload, client_len, error))
    return FALSE;

  g_autoptr(GPtrArray) client_replies = NULL;
  if (!goodix55a2_tls_flush (self, 3, &client_replies, error))
    return FALSE;

  if (!client_replies)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                   "TLS handshake did not emit server hello");
      return FALSE;
    }

  for (guint i = 0; i < client_replies->len; i++)
    {
      const guint8 *payload = NULL;
      gsize payload_len = 0;
      GByteArray *frame = g_ptr_array_index (client_replies, i);

      if (!goodix55a2_extract_payload (frame, &payload, &payload_len, error))
        return FALSE;

      if (!goodix55a2_tls_feed (self, payload, payload_len, error))
        return FALSE;
    }

  if (!goodix55a2_tls_flush (self, 0, NULL, error))
    return FALSE;

  if (!self->tls_ready)
    {
      int ret = SSL_do_handshake (self->ssl);
      if (ret == 1)
        self->tls_ready = TRUE;
      else
        {
          int ssl_err = SSL_get_error (self->ssl, ret);
          g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                       "TLS handshake incomplete (%d)", ssl_err);
          return FALSE;
        }
    }

  return TRUE;
}

static gboolean
goodix55a2_tls_decrypt (FpiDeviceGoodix55a2 *self,
                        gsize                expected_len,
                        GByteArray         **plaintext,
                        GError             **error)
{
  GByteArray *plain = g_byte_array_sized_new (expected_len);

  while (plain->len < expected_len)
    {
      guint8 buffer[2048];
      gsize want = MIN ((gsize) sizeof (buffer), expected_len - plain->len);
      int ret = SSL_read (self->ssl, buffer, want);

      if (ret > 0)
        {
          g_byte_array_append (plain, buffer, ret);
          continue;
        }

      int ssl_err = SSL_get_error (self->ssl, ret);
      if (ssl_err == SSL_ERROR_WANT_READ)
        {
          g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                       "TLS stream truncated");
          g_byte_array_unref (plain);
          return FALSE;
        }

      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                   "TLS read failed (%d)", ssl_err);
      g_byte_array_unref (plain);
      return FALSE;
    }

  *plaintext = plain;
  return TRUE;
}

static void
goodix55a2_unpack_frame (const guint8 *packed,
                         guint16      *unpacked)
{
  gsize out = 0;

  for (gsize i = 0; i < GOODIX55A2_PACKED_FRAME; i += 6)
    {
      guint8 c0 = packed[i + 0];
      guint8 c1 = packed[i + 1];
      guint8 c2 = packed[i + 2];
      guint8 c3 = packed[i + 3];
      guint8 c4 = packed[i + 4];
      guint8 c5 = packed[i + 5];

      unpacked[out++] = ((c0 & 0x0f) << 8) | c1;
      unpacked[out++] = (c3 << 4) | (c0 >> 4);
      unpacked[out++] = ((c5 & 0x0f) << 8) | c2;
      unpacked[out++] = (c4 << 4) | (c5 >> 4);
    }
}

static void
goodix55a2_fill_image (FpImage       *image,
                       const guint16 *values)
{
  for (guint row = 0; row < GOODIX55A2_SENSOR_WIDTH; row++)
    {
      for (guint col = 0; col < GOODIX55A2_SENSOR_HEIGHT; col++)
        {
          guint src_y = col;
          guint src_x = GOODIX55A2_SENSOR_WIDTH - 1 - row;
          guint16 sample = values[src_y * GOODIX55A2_SENSOR_WIDTH + src_x];
          guint16 value = sample >> 4;

          if (value > 255)
            value = 255;

          image->data[row * GOODIX55A2_SENSOR_HEIGHT + col] = (guint8) value;
        }
    }
}

static gboolean
goodix55a2_capture_frame (FpiDeviceGoodix55a2 *self,
                          FpImage            **out_image,
                          GError             **error)
{
  static const guint8 capture_req[] = { 0x01, 0x00 };
  g_autoptr(GPtrArray) replies = NULL;

  if (!goodix55a2_tls_handshake (self, error))
    return FALSE;

  if (!goodix55a2_send_command (self, 0x20, capture_req, sizeof (capture_req), 2, &replies, error))
    return FALSE;

  if (replies->len < 2)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                   "Capture reply missing image payload");
      return FALSE;
    }

  GByteArray *tls_frame = g_ptr_array_index (replies, replies->len - 1);
  const guint8 *tls_payload = NULL;
  gsize tls_len = 0;
  if (!goodix55a2_extract_payload (tls_frame, &tls_payload, &tls_len, error))
    return FALSE;

  if (!goodix55a2_tls_feed (self, tls_payload, tls_len, error))
    return FALSE;

  g_autoptr(GByteArray) plaintext = NULL;
  if (!goodix55a2_tls_decrypt (self, GOODIX55A2_PACKED_FRAME + GOODIX55A2_FRAME_CHECKSUM, &plaintext, error))
    return FALSE;

  if (plaintext->len < GOODIX55A2_PACKED_FRAME)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                   "Decrypted frame truncated (%u)", plaintext->len);
      return FALSE;
    }

  g_autofree guint16 *samples = g_new0 (guint16, GOODIX55A2_FRAME_PIXELS);
  goodix55a2_unpack_frame (plaintext->data, samples);

  FpImage *image = fp_image_new (GOODIX55A2_FRAME_WIDTH, GOODIX55A2_FRAME_HEIGHT);
  goodix55a2_fill_image (image, samples);
  goodix55a2_detrend_columns_u8 (image->data,
                                 GOODIX55A2_FRAME_WIDTH,
                                 GOODIX55A2_FRAME_HEIGHT);
  image->ppmm = GOODIX55A2_PPMM;
  *out_image = image;

  return TRUE;
}

static void
goodix55a2_handle_capture (FpiDeviceGoodix55a2 *self)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(FpImage) image = NULL;
  FpImageDevice *dev = FP_IMAGE_DEVICE (self);

  if (!goodix55a2_request_finger_detection (self, &error) ||
      !goodix55a2_capture_frame (self, &image, &error))
    {
      fpi_image_device_session_error (dev, g_steal_pointer (&error));
      return;
    }

  fpi_image_device_report_finger_status (dev, TRUE);
  fpi_image_device_image_captured (dev, g_steal_pointer (&image));
  fpi_image_device_report_finger_status (dev, FALSE);
}

static void
goodix55a2_dev_open (FpImageDevice *dev)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (dev);
  g_autoptr(GError) error = NULL;

  if (!g_usb_device_set_configuration (fpi_device_get_usb_device (FP_DEVICE (dev)), 1, &error))
    goto out;

  g_usb_device_claim_interface (fpi_device_get_usb_device (FP_DEVICE (dev)), 0, 0, &error);
  if (error == NULL)
    {
      if (!goodix55a2_initial_spi (self, &error) ||
          !goodix55a2_check_firmware (self, &error) ||
          !goodix55a2_update_psk (self, &error))
        {
          g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (dev)), 0, 0, NULL);
        }
      else
        {
          self->opened = TRUE;
        }
    }

out:
  fpi_image_device_open_complete (dev, g_steal_pointer (&error));
}

static void
goodix55a2_dev_close (FpImageDevice *dev)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (dev);

  if (self->ssl)
    {
      SSL_free (self->ssl);
      self->ssl = NULL;
      self->rbio = NULL;
      self->wbio = NULL;
    }

  if (self->ssl_ctx)
    {
      SSL_CTX_free (self->ssl_ctx);
      self->ssl_ctx = NULL;
    }

  g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (dev)), 0, 0, NULL);
  self->opened = FALSE;
  self->tls_ready = FALSE;

  fpi_image_device_close_complete (dev, NULL);
}

static void
goodix55a2_dev_activate (FpImageDevice *dev)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (dev);

  self->active = TRUE;
  fpi_image_device_activate_complete (dev, NULL);
}

static void
goodix55a2_dev_deactivate (FpImageDevice *dev)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (dev);

  self->active = FALSE;
  fpi_image_device_deactivate_complete (dev, NULL);
}

static void
goodix55a2_dev_change_state (FpImageDevice      *dev,
                             FpiImageDeviceState state)
{
  FpiDeviceGoodix55a2 *self = FPI_DEVICE_GOODIX55A2 (dev);

  if (!self->active)
    return;

  if (state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON)
    goodix55a2_handle_capture (self);
}

static const FpIdEntry goodix55a2_id_table[] = {
  { .vid = 0x27c6, .pid = 0x55a2 },
  { .vid = 0, .pid = 0 },
};

static void
fpi_device_goodix55a2_init (FpiDeviceGoodix55a2 *self)
{
}

static void
fpi_device_goodix55a2_class_init (FpiDeviceGoodix55a2Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  FpImageDeviceClass *img_class = FP_IMAGE_DEVICE_CLASS (klass);

  dev_class->id = FP_COMPONENT;
  dev_class->full_name = "Goodix 27c6:55a2 (TLS)";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->id_table = goodix55a2_id_table;

  img_class->img_width = GOODIX55A2_FRAME_WIDTH;
  img_class->img_height = GOODIX55A2_FRAME_HEIGHT;
  img_class->bz3_threshold = 24;
  img_class->img_open = goodix55a2_dev_open;
  img_class->img_close = goodix55a2_dev_close;
  img_class->activate = goodix55a2_dev_activate;
  img_class->deactivate = goodix55a2_dev_deactivate;
  img_class->change_state = goodix55a2_dev_change_state;
}
