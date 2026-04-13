#define FP_COMPONENT "goodix55a2"

#include "drivers_api.h"
#include "fpi-byte-utils.h"
#include "fpi-assembling.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ctype.h>
#include <string.h>

#define GOODIX55A2_EP_OUT   (0x01 | FPI_USB_ENDPOINT_OUT)
#define GOODIX55A2_EP_IN    (0x02 | FPI_USB_ENDPOINT_IN)

#define GOODIX55A2_SENSOR_WIDTH   56
#define GOODIX55A2_SENSOR_HEIGHT  176

/* the sensor frame is SENSOR_HEIGHT rows x SENSOR_WIDTH cols (176 x 56).
 * the outer border pixels are invalid:
 *   - first 3 and last 1 sensor rows are repeated/bogus fill values
 *   - first and last sensor columns are a constant fill value (0x5B)
 *   - additionally, the pixels near edge show bias, so we crop
 *     4 pixels from each edge to be safe
 *
 * the 56 pixel dimension of the 55a2 precludes the use of a single image
 * as it will not contain enough minutiae to be meaningful.  we will 
 * address this by treating it as a swipe sensor
 */
#define GOODIX55A2_CROP_ROWS_TOP    4   /* bogus repeated rows at sensor start   */
#define GOODIX55A2_CROP_ROWS_BOTTOM 4   /* trailing bad rows at sensor end        */
#define GOODIX55A2_CROP_COLS_LEFT   4   /* 2 fill columns at sensor left          */
#define GOODIX55A2_CROP_COLS_RIGHT  4   /* 4 invalid fill columns at sensor right */

#define GOODIX55A2_OUT_WIDTH   (GOODIX55A2_SENSOR_WIDTH  - GOODIX55A2_CROP_COLS_LEFT - GOODIX55A2_CROP_COLS_RIGHT)
#define GOODIX55A2_OUT_HEIGHT  (GOODIX55A2_SENSOR_HEIGHT - GOODIX55A2_CROP_ROWS_TOP  - GOODIX55A2_CROP_ROWS_BOTTOM)

/* swipe assembly: each sensor frame is rotated 90° before assembly so the
 * sensor long axis (170px) becomes the frame WIDTH and the short axis (50px)
 * becomes the frame HEIGHT.  the assembler then stacks frames top-to-bottom
 * as the finger swipes along the sensor, producing a wide landscape image
 * that gives NBIS enough columns for reliable minutiae detection.
 *
 * frame dimensions after rotation:
 *   SWIPE_FRAME_W = OUT_HEIGHT = ~170   (sensor long axis → image width)
 *   SWIPE_FRAME_H = OUT_WIDTH  =  ~50   (sensor short axis → image height)
 *
 * output image width is 4/3 of frame width to accommodate lateral drift.
 * min/max frames: require ≥5 frames to avoid spurious captures; we cap at 40.
 * finger-present threshold: mean pixel value >20 (after FPN+stretch).
 */
#define GOODIX55A2_SWIPE_FRAME_W   GOODIX55A2_OUT_HEIGHT   /* ~170 */
#define GOODIX55A2_SWIPE_FRAME_H   GOODIX55A2_OUT_WIDTH    /*  ~50 */
#define GOODIX55A2_SWIPE_IMG_W     (GOODIX55A2_SWIPE_FRAME_W * 4 / 3)  /* 226 */
#define GOODIX55A2_SWIPE_MIN_FRAMES  5
#define GOODIX55A2_SWIPE_MAX_FRAMES 40
#define GOODIX55A2_SWIPE_FINGER_THRESHOLD 20

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

  /* swipe assembly */
  GSList       *strips;
  gsize         strips_len;
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
  /* portrait orientation: sensor_row → image row (h=170), sensor_col → image col (w=51).
   *
   * in landscape the detrend ran along the sensor short-axis (56px) to correct
   * sensor column DC bias.  in portrait those same offsets lie along the image
   *
   * the FPN correction below handles the 4-channel inter-row DC offsets.
   * the contrast stretch handles any remaining column-mean variation.
   */

  /* fixed pattern noise (FPN) correction.
   *
   * the sensor has 4 interleaved readout channels cycling across sensor
   * ROWS.  in portrait orientation, sensor rows = image rows, so the 4
   * channels repeat every 4 rows (y % 4 == channel).
   * we equalise each channel's mean to the global image mean.
   */
  {
    double global_sum = 0;
    gsize  n          = (gsize) w * h;

    for (gsize i = 0; i < n; i++)
      global_sum += img[i];
    double global_mean = global_sum / n;

    for (int ch = 0; ch < 4; ch++)
      {
        double ch_sum = 0;
        gsize  ch_n   = 0;

        for (int y = ch; y < h; y += 4)
          for (int x = 0; x < w; x++)
            {
              ch_sum += img[y * w + x];
              ch_n++;
            }

        if (ch_n == 0)
          continue;

        double offset = global_mean - (ch_sum / ch_n);

        for (int y = ch; y < h; y += 4)
          for (int x = 0; x < w; x++)
            {
              double v = (double) img[y * w + x] + offset;
              if (v < 0)   v = 0;
              if (v > 255) v = 255;
              img[y * w + x] = (guint8) v;
            }
      }
  }

  /* percentile contrast stretch
   *
   * a naive min/max stretch is fooled by a handful of outlier pixels that
   * happen to hit the extremes, leaving the bulk of the image (where the
   * actual ridge/valley signal lives) barely expanded.  while cropping the
   * outer pixels alleviates this to some extent, we shall additionally map the
   * 2nd percentile to 0 and the 98th percentile to 255 to force the
   * central bulk of the histogram to use the full range and gives NBIS
   * much more signal to work with when binarising ridges and valleys.
   */
  {
    gsize   n    = (gsize) w * h;
    guint32 hist[256] = { 0 };

    for (gsize i = 0; i < n; i++)
      hist[img[i]]++;

    /* map the 10th–90th percentile to 0–255.  a wider clip (e.g. p2/p98)
     * leaves the bulk of the signal in too narrow a range for NBIS to
     * binarise reliably; p10/p90 discards more outliers but expands the
     * central ridge/valley signal to use the full 8-bit range, raising
     * local contrast from <16 to >32 counts — well above NBIS threshold. */
    gsize lo_target = (n * 10) / 100;
    gsize cumulative = 0;
    guint8 lo = 0;
    for (int v = 0; v < 256; v++)
      {
        cumulative += hist[v];
        if (cumulative >= lo_target) { lo = (guint8) v; break; }
      }

    /* find 90th-percentile value */
    gsize hi_target = (n * 90) / 100;
    cumulative = 0;
    guint8 hi = 255;
    for (int v = 0; v < 256; v++)
      {
        cumulative += hist[v];
        if (cumulative >= hi_target) { hi = (guint8) v; break; }
      }

    if (hi > lo)
      {
        for (gsize i = 0; i < n; i++)
          {
            int v = (((int) img[i] - lo) * 255) / (hi - lo);
            if (v < 0)   v = 0;
            if (v > 255) v = 255;
            img[i] = (guint8) v;
          }
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
  /* copy sensor data into the output image in PORTRAIT orientation,
   * cropping the invalid border pixels.
   */
  for (guint out_row = 0; out_row < GOODIX55A2_OUT_HEIGHT; out_row++)
    {
      guint sensor_row = out_row + GOODIX55A2_CROP_ROWS_TOP;

      for (guint out_col = 0; out_col < GOODIX55A2_OUT_WIDTH; out_col++)
        {
          guint   sensor_col = out_col + GOODIX55A2_CROP_COLS_LEFT;
          guint16 sample     = values[sensor_row * GOODIX55A2_SENSOR_WIDTH + sensor_col];
          guint16 value      = sample >> 4;

          if (value > 255)
            value = 255;

          image->data[out_row * GOODIX55A2_OUT_WIDTH + out_col] = (guint8) value;
        }
    }
}

/* custom swipe movement estimation
 * fpi_do_movement_estimation() search for dx in [-8,+8] and accumulates those
 * offsets across all frames, causing a staircase artifact when small per-frame
 * dx errors sum to large total displacements
 *
 * this replacement forces delta_x=0 and computes delta_y by 1D cross-
 * correlation along the stripe height only (dy search: 1..MAX_DY)
 * MAX_DY = SWIPE_FRAME_H/2 = 25px, which corresponds to ~12mm/s swipe speed
 * at 500dpi and ~48fps therefore fast enough for any realistic swipe
 */
#define GOODIX55A2_MAX_DY  (GOODIX55A2_SWIPE_FRAME_H / 2)   /* 25 */

static void
goodix55a2_movement_estimation (GSList *stripes,
                                struct fpi_frame_asmbl_ctx *ctx)
{
  struct fpi_frame *prev = stripes->data;
  /* first frame has no delta */
  prev->delta_x = 0;
  prev->delta_y = 0;

  for (GSList *l = stripes->next; l != NULL; l = l->next)
    {
      struct fpi_frame *cur = l->data;
      cur->delta_x = 0;

      /* find best dy by minimising mean absolute error at each candidate.
       * trim 8px from each side (noisy sensor edges) and use only the
       * central rows for comparison to improve accuracy.
       */
#define GOODIX55A2_EDGE_TRIM  8
      guint  errs[GOODIX55A2_MAX_DY + 1];
      guint  best_err = G_MAXUINT;
      int    best_dy  = 1;
      guint  x0 = GOODIX55A2_EDGE_TRIM;
      guint  x1 = ctx->frame_width - GOODIX55A2_EDGE_TRIM;

      for (int dy = 1; dy <= GOODIX55A2_MAX_DY; dy++)
        {
          guint err = 0;
          guint h   = ctx->frame_height - dy;

          for (guint y = 0; y < h; y++)
            for (guint x = x0; x < x1; x++)
              {
                guint8 a = ctx->get_pixel (ctx, prev, x, y + dy);
                guint8 b = ctx->get_pixel (ctx, cur,  x, y);
                err += a > b ? a - b : b - a;
              }

          /* normalise so all dy values are comparable */
          errs[dy] = (err * ctx->frame_height) / h;

          if (errs[dy] < best_err)
            {
              best_err = errs[dy];
              best_dy  = dy;
            }
        }

      cur->delta_y = best_dy;
      prev = cur;
    }
}

/* swipe frame pixel accessor (rotated: frame_x=sensor_row, frame_y=sensor_col) */
static unsigned char
goodix55a2_get_pixel (struct fpi_frame_asmbl_ctx *ctx,
                      struct fpi_frame           *frame,
                      unsigned int                x,
                      unsigned int                y)
{
  return frame->data[x + y * ctx->frame_width];
}

static struct fpi_frame_asmbl_ctx goodix55a2_asmbl_ctx = {
  .frame_width  = GOODIX55A2_SWIPE_FRAME_W,
  .frame_height = GOODIX55A2_SWIPE_FRAME_H,
  .image_width  = GOODIX55A2_SWIPE_FRAME_W,
  .get_pixel    = goodix55a2_get_pixel,
};

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

  FpImage *image = fp_image_new (GOODIX55A2_OUT_WIDTH, GOODIX55A2_OUT_HEIGHT);
  goodix55a2_fill_image (image, samples);
  goodix55a2_detrend_columns_u8 (image->data,
                                 GOODIX55A2_OUT_WIDTH,
                                 GOODIX55A2_OUT_HEIGHT);
  image->ppmm  = GOODIX55A2_PPMM;
  /* GF3206 is of capacitive type sensor: ridges produce HIGH signal (bright).
   * NBIS expects dark ridges; FP_IMAGE_INVERTED tells libfprint to invert
   * the image before handing it to NBIS */
  image->flags = FPI_IMAGE_COLORS_INVERTED;
  *out_image = image;

  return TRUE;
}

/* compute mean of processed pixel buffer (0-255 range)
 * use to detect finger presence: background ≈ 0, finger > threshold */
static guint
goodix55a2_frame_mean (const guint8 *data, gsize len)
{
  guint64 sum = 0;
  for (gsize i = 0; i < len; i++)
    sum += data[i];
  return (guint)(sum / len);
}

/* mean absolute difference between two frames — detects inter-frame motion. */
static guint
goodix55a2_frame_diff (const guint8 *a, const guint8 *b, gsize len)
{
  guint64 sum = 0;
  for (gsize i = 0; i < len; i++)
    sum += a[i] > b[i] ? a[i] - b[i] : b[i] - a[i];
  return (guint)(sum / len);
}

static void
goodix55a2_handle_capture (FpiDeviceGoodix55a2 *self)
{
  g_autoptr(GError) error = NULL;
  FpImageDevice *dev = FP_IMAGE_DEVICE (self);

  /* discard any leftover strips from a previous interrupted swipe */
  if (self->strips)
    {
      g_slist_free_full (self->strips, g_free);
      self->strips = NULL;
      self->strips_len = 0;
    }

  /* send finger-detection configuration to sensor (non-blocking) */
  if (!goodix55a2_request_finger_detection (self, &error))
    {
      fpi_image_device_session_error (dev, g_steal_pointer (&error));
      return;
    }

  /* capture loop: accumulate frames while finger is present and moving
   *
   * swipe end is detected by two ways:
   *   1. mean drops below threshold, assume finger lifted
   *   2. inter-frame MAD drops below STATIC_THRESHOLD, assume finger stopped moving
   *
   * STATIC_THRESHOLD: mean absolute difference per pixel below which we
   * consider the finger stationary.  a moving finger gives MAD ~15-30;
   * a static press gives MAD ~2-5.
   */
#define GOODIX55A2_SWIPE_STATIC_THRESHOLD  12
#define GOODIX55A2_SWIPE_STATIC_FRAMES     4

  gboolean finger_seen    = FALSE;
  gboolean finger_moving  = FALSE;
  guint    static_count   = 0;
  gsize    frame_bytes    = GOODIX55A2_SWIPE_FRAME_W * GOODIX55A2_SWIPE_FRAME_H;
  gsize    px_len         = GOODIX55A2_OUT_WIDTH * GOODIX55A2_OUT_HEIGHT;
  g_autofree guint8 *prev_pixels = g_malloc0 (px_len);

  for (gsize i = 0; i < GOODIX55A2_SWIPE_MAX_FRAMES; i++)
    {
      g_autoptr(FpImage) frame_img = NULL;

      if (!goodix55a2_capture_frame (self, &frame_img, &error))
        {
          fpi_image_device_session_error (dev, g_steal_pointer (&error));
          return;
        }

      guint mean = goodix55a2_frame_mean (frame_img->data, px_len);
      gboolean finger_present = (mean > GOODIX55A2_SWIPE_FINGER_THRESHOLD);

      if (!finger_present)
        {
          if (finger_seen)
            break;   /* finger lifted — end of swipe */
          memcpy (prev_pixels, frame_img->data, px_len);
          continue;
        }

      /* finger is present */
      if (!finger_seen)
        {
          finger_seen = TRUE;
          fpi_image_device_report_finger_status (dev, TRUE);
          memcpy (prev_pixels, frame_img->data, px_len);
          continue;  /* skip first touch frame */
        }

      /* detect motion via inter-frame difference */
      guint diff = goodix55a2_frame_diff (frame_img->data, prev_pixels, px_len);
      memcpy (prev_pixels, frame_img->data, px_len);

      if (diff > GOODIX55A2_SWIPE_STATIC_THRESHOLD)
        {
          if (!finger_moving)
            {
              /* first movement detected — discard pre-movement strips */
              fp_dbg ("First movement at frame %zu (diff=%u), discarding %zu pre-movement strips",
                      i, diff, self->strips_len);
              g_slist_free_full (self->strips, g_free);
              self->strips = NULL;
              self->strips_len = 0;
            }
          finger_moving = TRUE;
          static_count = 0;
        }
      else
        {
          static_count++;
          if (finger_moving && static_count >= GOODIX55A2_SWIPE_STATIC_FRAMES)
            {
              fp_dbg ("Swipe ended: finger static for %u frames (diff=%u)", static_count, diff);
              /* discard the trailing static frames — finger was stopping/lifted */
              for (guint s = 0; s < static_count && self->strips; s++)
                {
                  g_free (self->strips->data);
                  self->strips = g_slist_delete_link (self->strips, self->strips);
                  self->strips_len--;
                }
              break;
            }
          /* skip storing frames while finger is slowing/static */
          if (finger_moving && static_count > 0)
            continue;
        }

      /* only store frames during active movement */
      if (!finger_moving)
        continue;

      /* store rotated stripe: sensor long axis → frame width (x), short → height (y)
       * dst[x + y * FRAME_W] = src[x * OUT_WIDTH + y] */
      struct fpi_frame *stripe = g_malloc (sizeof (struct fpi_frame) + frame_bytes);
      stripe->delta_x = 0;
      stripe->delta_y = 0;

      /* per-frame contrast stretch (p5..p95) to normalise brightness
       * and eliminate visible seams when assembling */
      guint hist[256] = {0};
      for (gsize p = 0; p < px_len; p++)
        hist[frame_img->data[p]]++;

      /* find p5 and p95 */
      guint lo = 0, hi = 255;
      guint target_lo = (guint)(px_len * 5  / 100);
      guint target_hi = (guint)(px_len * 95 / 100);
      guint cum = 0;
      for (guint b = 0; b < 256; b++) {
        cum += hist[b];
        if (cum >= target_lo && lo == 0) lo = b;
        if (cum >= target_hi) { hi = b; break; }
      }
      if (hi <= lo) hi = lo + 1;

      for (guint x = 0; x < GOODIX55A2_SWIPE_FRAME_W; x++)
        for (guint y = 0; y < GOODIX55A2_SWIPE_FRAME_H; y++)
          {
            guint8 raw = frame_img->data[x * GOODIX55A2_OUT_WIDTH + y];
            gint   v   = (gint)(raw - lo) * 255 / (gint)(hi - lo);
            stripe->data[x + y * GOODIX55A2_SWIPE_FRAME_W] =
              (guint8) CLAMP (v, 0, 255);
          }

      self->strips = g_slist_prepend (self->strips, stripe);
      self->strips_len++;
    }

  if (!finger_seen || self->strips_len < GOODIX55A2_SWIPE_MIN_FRAMES)
    {
      /* no usable swipe... clean up and wait for next attempt */
      if (self->strips)
        {
          g_slist_free_full (self->strips, g_free);
          self->strips = NULL;
          self->strips_len = 0;
        }
      fpi_image_device_retry_scan (dev, FP_DEVICE_RETRY_TOO_SHORT);
      return;
    }

  /* Assemble strips into a single image */
  fp_dbg ("Assembling %zu swipe frames", self->strips_len);

  /* require minimum strip count for a valid swipe.
   * SWIPE_MIN_FRAMES=5 is already checked above, but also enforce
   * that we have enough frames to produce a useful image. */
  if (self->strips_len < GOODIX55A2_SWIPE_MIN_FRAMES)
    {
      g_slist_free_full (self->strips, g_free);
      self->strips = NULL;
      self->strips_len = 0;
      fpi_image_device_report_finger_status (dev, FALSE);
      return;
    }
  self->strips = g_slist_reverse (self->strips);
  goodix55a2_movement_estimation (self->strips, &goodix55a2_asmbl_ctx);
  g_autoptr(FpImage) assembled = fpi_assemble_frames (&goodix55a2_asmbl_ctx, self->strips);

  g_slist_free_full (self->strips, g_free);
  self->strips = NULL;
  self->strips_len = 0;

  assembled->ppmm  = GOODIX55A2_PPMM;
  assembled->flags |= FPI_IMAGE_COLORS_INVERTED;

  fpi_image_device_image_captured (dev, g_steal_pointer (&assembled));
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
  dev_class->scan_type = FP_SCAN_TYPE_SWIPE;
  dev_class->id_table = goodix55a2_id_table;

  /* swipe-assembled image dimensions img_width/img_height are used by
   * libfprint to allocate NBIS buffers; they must match the assembled output.
   * image_width = 226 (4/3 * 170), height is variable but set to a generous
   * maximum so libfprint pre-allocates enough. 0 = let libfprint use actual. */
  img_class->img_width  = GOODIX55A2_SWIPE_FRAME_W;  /* 170 — no side padding */
  img_class->img_height = 0;   /* variable: set by assembled image */
  /* swipe mode assembles 5-40 frames into a ~226×400px image, yielding
   * 15-30 minutiae */
  img_class->bz3_threshold = 24;
  img_class->img_open = goodix55a2_dev_open;
  img_class->img_close = goodix55a2_dev_close;
  img_class->activate = goodix55a2_dev_activate;
  img_class->deactivate = goodix55a2_dev_deactivate;
  img_class->change_state = goodix55a2_dev_change_state;
}
