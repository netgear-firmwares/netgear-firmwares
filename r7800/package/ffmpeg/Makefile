#
# Copyright (C) 2006-2016 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=ffmpeg
PKG_VERSION:=2.6.9
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=http://ffmpeg.org/releases/
PKG_MD5SUM:=c3bdcce6f5ea0d138cae57ee38affa39
PKG_MAINTAINER:=Ted Hess <thess@kitschensync.net>

PKG_LICENSE:=LGPL-2.1+ GPL-2+ LGPL-3
PKG_LICENSE_FILES:=COPYING.GPLv2 COPYING.GPLv3 COPYING.LGPLv2.1 COPYING.LGPLv3

FFMPEG_CUSTOM_ENCODERS:= \
	ac3 \
	jpegls \
	mpeg1video \
	mpeg2video \
	mpeg4 \
	pcm_s16be \
	pcm_s16le \
	png \
	vorbis \
	zlib \

FFMPEG_CUSTOM_DECODERS:= \
	aac \
	ac3 \
	alac \
	amrnb \
	amrwb \
	ape \
	atrac3 \
	flac \
	gif \
	h264 \
	jpegls \
	mp2 \
	mp3 \
	mpeg1video \
	mpeg2video \
	mpeg4 \
	mpegvideo \
	mpc7 \
	mpc8 \
	pcm_s16be \
	pcm_s16le \
	png \
	vorbis \
	wavpack \
	wmav1 \
	wmav2 \
	zlib \

FFMPEG_CUSTOM_MUXERS:= \
	ac3 \
	ffm \
	h264 \
	mp3 \
	mp4 \
	mpeg1video \
	mpeg2video \
	mpegts \
	ogg \
	rtp \

FFMPEG_CUSTOM_DEMUXERS:= \
	aac \
	ac3 \
	amr \
	ape \
	avi \
	flac \
	ffm \
	h264 \
	matroska \
	mov \
	mp3 \
	mpegps \
	mpegts \
	mpegvideo \
	mpc \
	mpc8 \
	ogg \
	rm \
	rtsp \
	rtp \
	sdp \
	v4l2 \
	wav \
	wv \

FFMPEG_CUSTOM_PARSERS:= \
	aac \
	flac \
	ac3 \
	h264 \
	mpegaudio \
	mpeg4video \
	mpegvideo \

FFMPEG_CUSTOM_PROTOCOLS:= \
	file http icecast pipe rtp tcp udp

FFMPEG_MINI_DECODERS:= \
	aac \
	ac3 \
	flac \
	h264 \
	jpegls \
	mp3 \
	mpeg1video \
	mpeg2video \
	mpeg4 \
	mpegvideo \
	png \
	wmav1 \
	wmav2 \

FFMPEG_MINI_DEMUXERS := \
	aac \
	ac3 \
	avi \
	flac \
	h264 \
	matroska \
	mov \
	mp3 \
	mpegts \
	mpegvideo \

FFMPEG_MINI_PARSERS:= \
	ac3 \
	flac \
	h264 \
	mpeg4video \
	mpegaudio \

FFMPEG_MINI_PROTOCOLS := \
	file \

FFMPEG_AUDIO_DECODERS:= \
	aac \
	aac_latm \
	ac3 \
	adpcm_* \
	alac \
	amrnb \
	amrwb \
	ape \
	atrac3 \
	flac \
	mp2 \
	mp3* \
	mpc7 \
	mpc8 \
	pcm_* \
	vorbis \
	wavpack \
	wmav1 \
	wmav2 \
	wmalossless \
	wmapro \
	zlib \

FFMPEG_AUDIO_DEMUXERS:= \
	aac \
	ac3 \
	aiff \
	amr \
	ape \
	avi \
	flac \
	ffm \
	matroska \
	mp3 \
	mov \
	mpc \
	mpc8 \
	mpegts \
	ogg \
	rm \
	rtsp \
	rtp \
	sdp \
	wav \
	wv \

FFMPEG_AUDIO_PARSERS:= \
	aac \
	aac_latm \
	flac \
	ac3 \
	mpegaudio \

FFMPEG_AUDIO_PROTOCOLS:= \
	file http icecast rtp tcp udp


PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(BUILD_VARIANT)/$(PKG_NAME)-$(PKG_VERSION)

PKG_CONFIG_DEPENDS:= \
	$(patsubst %,CONFIG_FFMPEG_CUSTOM_ENCODER_%,$(FFMPEG_CUSTOM_ENCODERS)) \
	$(patsubst %,CONFIG_FFMPEG_CUSTOM_DECODER_%,$(FFMPEG_CUSTOM_DECODERS)) \
	$(patsubst %,CONFIG_FFMPEG_CUSTOM_MUXER_%,$(FFMPEG_CUSTOM_DEMUXERS)) \
	$(patsubst %,CONFIG_FFMPEG_CUSTOM_DEMUXER_%,$(FFMPEG_CUSTOM_DEMUXERS)) \
	$(patsubst %,CONFIG_FFMPEG_CUSTOM_PARSER_%,$(FFMPEG_CUSTOM_PARSERS)) \
	$(patsubst %,CONFIG_FFMPEG_CUSTOM_PROTOCOL_%,$(FFMPEG_CUSTOM_PROTOCOLS))

include $(INCLUDE_DIR)/package.mk

define Package/ffmpeg/Default
 TITLE:=FFmpeg
 URL:=http://ffmpeg.mplayerhq.hu/
endef

define Package/ffmpeg/Default/description
 FFmpeg is a a software package that can record, convert and stream digital
 audio and video in numerous formats.
endef


define Package/ffmpeg
$(call Package/ffmpeg/Default)
 SECTION:=multimedia
 CATEGORY:=Multimedia
 TITLE+= program
 DEPENDS+= +libpthread +libffmpeg-full
 VARIANT:=full
endef

define Package/ffmpeg/description
$(call Package/ffmpeg/Default/description)
 .
 This package contains the FFmpeg command line tool.
endef


define Package/ffprobe
$(call Package/ffmpeg/Default)
 SECTION:=multimedia
 CATEGORY:=Multimedia
 TITLE+= CLI media identifier
 DEPENDS+= +libffmpeg-full
 VARIANT:=full
endef

define Package/ffprobe/description
$(call Package/ffmpeg/Default/description)
 .
 This package contains the FFprobe command line tool.
endef


define Package/ffserver
$(call Package/ffserver/Default)
 SECTION:=multimedia
 CATEGORY:=Multimedia
 TITLE+= streaming server
 DEPENDS+= +libpthread +libffmpeg-full
 VARIANT:=full
endef

define Package/ffserver/description
$(call Package/ffmpeg/Default/description)
 .
 This package contains the FFmpeg streaming server.
endef


define Package/libffmpeg/Default
$(call Package/ffmpeg/Default)
 SECTION:=libs
 CATEGORY:=Libraries
 TITLE+= libraries
 DEPENDS+= +libpthread +zlib +libbz2
 PROVIDES:= libffmpeg
endef


define Package/libffmpeg-custom
$(call Package/libffmpeg/Default)
 TITLE+= (custom)
 DEPENDS+= @DEVEL @!ALL +libopus +libspeex
 VARIANT:=custom
 MENU:=1
endef

define Package/libffmpeg-custom/config
source "$(SOURCE)/Config.in"
endef

define Package/libffmpeg-custom/description
$(call Package/ffmpeg/Default/description)
 .
 This package contains customized FFmpeg shared libraries.
endef


define Package/libffmpeg-audio-dec
$(call Package/libffmpeg/Default)
 TITLE+= (audio)
 DEPENDS+= @DEVEL +libopus +libspeex
 VARIANT:=audio-dec
endef

define Package/libffmpeg-audio-dec/description
$(call Package/ffmpeg/Default/description)
 .
 This package contains FFmpeg shared libraries for audio decoding
endef


define Package/libffmpeg-full
$(call Package/libffmpeg/Default)
 TITLE+= (full)
 DEPENDS+= @BUILD_PATENTED +alsa-lib
 VARIANT:=full
endef

define Package/libffmpeg-full/description
$(call Package/ffmpeg/Default/description)
 .
 This package contains full-featured FFmpeg shared libraries.
endef


define Package/libffmpeg-mini
$(call Package/libffmpeg/Default)
 TITLE+= (mini)
 DEPENDS+= @BUILD_PATENTED
 VARIANT:=mini
endef

define Package/libffmpeg-mini/description
$(call Package/ffmpeg/Default/description)
 .
 This package contains minimal-featured FFmpeg shared libraries.
endef


FFMPEG_CONFIGURE:= \
	CFLAGS="$(TARGET_CFLAGS) $(TARGET_CPPFLAGS) $(FPIC)" \
	LDFLAGS="$(TARGET_LDFLAGS)" \
	./configure \
	--enable-cross-compile \
	--cross-prefix="$(TARGET_CROSS)" \
	--arch="$(ARCH)" \
	--target-os=linux \
	--prefix="/usr" \
	--pkg-config="pkg-config" \
	--enable-shared \
	--enable-static \
	--disable-debug \
	\
	--enable-gpl \
	--enable-version3 \
	\
	--disable-asm \
	--disable-doc \
	--disable-dxva2 \
	--enable-pthreads \
	--disable-optimizations \
	--enable-small \
	--disable-stripping \
	--enable-zlib \
	--disable-ffmpeg \
	--disable-ffplay \
	--disable-ffprobe \
	--disable-ffserver \
	--disable-avfilter \
	--disable-postproc \
	--disable-muxers \
	--disable-encoders \
	--disable-protocols \
	--enable-protocol=file \
	--disable-decoder=twinvq \
	--disable-decoder=dca \
	--disable-decoder=ralf \
	--disable-decoder=rv30 \
	--disable-decoder=rv40 \
	--disable-decoder=vc1 \
	--disable-decoder=wmavoice \
	--disable-decoder=dirac \
	--disable-decoder=dnxhd \
	--disable-decoder=mjpeg \
	--disable-decoder=mlp \
	--disable-decoder=vp3 \
	--disable-decoder=ape \
	--disable-decoder=ass \
	--disable-decoder=bethsoftvid \
	--disable-decoder=bfi \
	--disable-decoder=c93 \
	--disable-decoder=dxa \
	--disable-decoder=gsm \
	--disable-decoder=idcin \
	--disable-decoder=rawvideo \
	--disable-decoder=rl2 \
	--disable-decoder=roq \
	--disable-decoder=shorten \
	--disable-decoder=smacker \
	--disable-decoder=thp \
	--disable-decoder=tta \
	--disable-decoder=txd \
	--disable-parser=cavsvideo \
	--disable-parser=dca \
	--disable-parser=dirac \
	--disable-parser=dnxhd \
	--disable-parser=mjpeg \
	--disable-parser=mlp \
	--disable-parser=pnm \
	--disable-parser=vp3 \
	--disable-demuxer=amr \
	--disable-demuxer=apc \
	--disable-demuxer=ape \
	--disable-demuxer=ass \
	--disable-demuxer=bethsoftvid \
	--disable-demuxer=bfi \
	--disable-demuxer=c93 \
	--disable-demuxer=daud \
	--disable-demuxer=dnxhd \
	--disable-demuxer=dsicin \
	--disable-demuxer=dxa \
	--disable-demuxer=gsm \
	--disable-demuxer=gxf \
	--disable-demuxer=idcin \
	--disable-demuxer=iff \
	--disable-demuxer=image2 \
	--disable-demuxer=image2pipe \
	--disable-demuxer=ingenient \
	--disable-demuxer=ipmovie \
	--disable-demuxer=lmlm4 \
	--disable-demuxer=mm \
	--disable-demuxer=mmf \
	--disable-demuxer=msnwc_tcp \
	--disable-demuxer=mtv \
	--disable-demuxer=mxf \
	--disable-demuxer=nsv \
	--disable-demuxer=nut \
	--disable-demuxer=oma \
	--disable-demuxer=pva \
	--disable-demuxer=rawvideo \
	--disable-demuxer=rl2 \
	--disable-demuxer=roq \
	--disable-demuxer=rpl \
	--disable-demuxer=segafilm \
	--disable-demuxer=shorten \
	--disable-demuxer=siff \
	--disable-demuxer=smacker \
	--disable-demuxer=sol \
	--disable-demuxer=str \
	--disable-demuxer=thp \
	--disable-demuxer=tiertexseq \
	--disable-demuxer=tta \
	--disable-demuxer=txd \
	--disable-demuxer=vmd \
	--disable-demuxer=voc \
	--disable-demuxer=wc3 \
	--disable-demuxer=wsaud \
	--disable-demuxer=wsvqa \
	--disable-demuxer=xa \
	--disable-demuxer=yuv4mpegpipe \
	--disable-outdevs

ifeq ($(BUILD_VARIANT),custom)

  FFMPEG_ENABLE= \
	$(foreach c, $(2), \
		$(if $($(3)_$(c)),--enable-$(1)="$(c)") \
	)

  FFMPEG_CONFIGURE+= \
	--disable-programs \
	--disable-avfilter \
	--disable-postproc \
	--disable-swresample \
	--disable-swscale \
	--disable-everything \
	$(call FFMPEG_ENABLE,encoder,$(FFMPEG_CUSTOM_ENCODERS),CONFIG_FFMPEG_CUSTOM_ENCODER) \
	$(call FFMPEG_ENABLE,decoder,$(FFMPEG_CUSTOM_DECODERS),CONFIG_FFMPEG_CUSTOM_DECODER) \
	$(call FFMPEG_ENABLE,muxer,$(FFMPEG_CUSTOM_MUXERS),CONFIG_FFMPEG_CUSTOM_MUXER) \
	$(call FFMPEG_ENABLE,demuxer,$(FFMPEG_CUSTOM_DEMUXERS),CONFIG_FFMPEG_CUSTOM_DEMUXER) \
	$(call FFMPEG_ENABLE,parser,$(FFMPEG_CUSTOM_PARSERS),CONFIG_FFMPEG_CUSTOM_PARSER) \
	$(call FFMPEG_ENABLE,protocol,$(FFMPEG_CUSTOM_PROTOCOLS),CONFIG_FFMPEG_CUSTOM_PROTOCOL) \

ifeq ($(CONFIG_FFMPEG_CUSTOM_SELECT_adpcm),y)
  FFMPEG_CONFIGURE+= \
	--enable-decoder=adpcm_ima_wav \
	--enable-decoder=adpcm_ima_qt \
	--enable-decoder=adpcm_ms \

endif

ifeq ($(CONFIG_FFMPEG_CUSTOM_SELECT_libopus),y)
  FFMPEG_CONFIGURE+= \
	--enable-libopus --enable-decoder=libopus \

endif

ifeq ($(CONFIG_FFMPEG_CUSTOM_SELECT_speex),y)
  FFMPEG_CONFIGURE+= \
	--enable-libspeex --enable-decoder=libspeex \

endif

endif

ifeq ($(BUILD_VARIANT),audio-dec)

  FFMPEG_ENABLE= \
	$(foreach c, $(2), \
		--enable-$(1)="$(c)" \
	)

  FFMPEG_CONFIGURE+= \
	--disable-programs \
	--disable-avfilter \
	--disable-postproc \
	--disable-swresample \
	--disable-swscale \
	--disable-everything \
	$(call FFMPEG_ENABLE,decoder,$(FFMPEG_AUDIO_DECODERS)) \
	$(call FFMPEG_ENABLE,demuxer,$(FFMPEG_AUDIO_DEMUXERS)) \
	$(call FFMPEG_ENABLE,parser,$(FFMPEG_AUDIO_PARSERS)) \
	$(call FFMPEG_ENABLE,protocol,$(FFMPEG_AUDIO_PROTOCOLS)) \
	--enable-libopus --enable-decoder=libopus \
	--enable-libspeex --enable-decoder=libspeex \
	--disable-decoder=pcm_bluray,pcm_dvd \

endif

ifeq ($(BUILD_VARIANT),mini)

  FFMPEG_ENABLE= \
	$(foreach c, $(2), \
		--enable-$(1)="$(c)" \
	)

  FFMPEG_CONFIGURE+= \
	--disable-programs \
	--disable-avdevice \
	--disable-avfilter \
	--disable-postproc \
	--disable-swresample \
	--disable-swscale \
	--disable-everything \
	$(call FFMPEG_ENABLE,decoder,$(FFMPEG_MINI_DECODERS)) \
	$(call FFMPEG_ENABLE,demuxer,$(FFMPEG_MINI_DEMUXERS)) \
	$(call FFMPEG_ENABLE,parser,$(FFMPEG_MINI_PARSERS)) \
	$(call FFMPEG_ENABLE,protocol,$(FFMPEG_MINI_PROTOCOLS)) \

endif

ifneq ($(CONFIG_TARGET_x86),)
  TARGET_CFLAGS += -fomit-frame-pointer
endif

define Build/Configure
	( cd $(PKG_BUILD_DIR); $(FFMPEG_CONFIGURE) )
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
endef

define Build/InstallDev/custom
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/lib{avcodec,avdevice,avformat,avutil} $(1)/usr/include/
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/lib{avcodec,avdevice,avformat,avutil}.{a,so*} $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/lib{avcodec,avdevice,avformat,avutil}.pc $(1)/usr/lib/pkgconfig/
endef

define Build/InstallDev/full
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/lib{avcodec,avdevice,avformat,avutil,swresample,swscale} $(1)/usr/include/
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/lib{avcodec,avdevice,avformat,avutil,swresample,swscale}.{a,so*} $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/lib{avcodec,avdevice,avformat,avutil,swresample,swscale}.pc $(1)/usr/lib/pkgconfig/
endef

define Build/InstallDev/mini
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/lib{avcodec,avformat,avutil} $(1)/usr/include/
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/lib{avcodec,avformat,avutil}.{a,so*} $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/lib{avcodec,avformat,avutil}.pc $(1)/usr/lib/pkgconfig/
endef

Build/InstallDev/audio-dec = $(Build/InstallDev/custom)

# XXX: attempt at installing "best" dev files available
ifeq ($(BUILD_VARIANT),custom)
  # XXX: only install "custom" dev files if -full & -mini are not selected
  ifeq ($(CONFIG_PACKAGE_libffmpeg-full)$(CONFIG_PACKAGE_libffmpeg-mini),)
    Build/InstallDev = $(Build/InstallDev/custom)
  endif
endif
ifeq ($(BUILD_VARIANT),audio-dec)
  # XXX: only install "audio-dec" dev files if -full & -mini are not selected
  ifeq ($(CONFIG_PACKAGE_libffmpeg-full)$(CONFIG_PACKAGE_libffmpeg-mini),)
    Build/InstallDev = $(Build/InstallDev/audio-dec)
  endif
endif
ifeq ($(BUILD_VARIANT),full)
  # XXX: always install "full" dev files if -full is selected
  Build/InstallDev = $(Build/InstallDev/full)
endif
ifeq ($(BUILD_VARIANT),mini)
  # XXX: only install "mini" dev files if -full is not selected
  ifeq ($(CONFIG_PACKAGE_libffmpeg-full),)
    Build/InstallDev = $(Build/InstallDev/mini)
  endif
endif

define Package/ffmpeg/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/ffmpeg $(1)/usr/bin/
endef

define Package/ffprobe/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/ffprobe $(1)/usr/bin/
endef

define Package/ffserver/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/ffserver $(1)/usr/bin/
endef

define Package/libffmpeg-custom/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/lib{avcodec,avdevice,avformat,avutil}.so.* $(1)/usr/lib/
endef

define Package/libffmpeg-full/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/lib{avcodec,avdevice,avformat,avutil,swresample,swscale}.so.* $(1)/usr/lib/
endef

define Package/libffmpeg-mini/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/lib{avcodec,avformat,avutil}.so.* $(1)/usr/lib/
endef

Package/libffmpeg-audio-dec/install = $(Package/libffmpeg-custom/install)

$(eval $(call BuildPackage,ffmpeg))
$(eval $(call BuildPackage,ffprobe))
$(eval $(call BuildPackage,ffserver))
$(eval $(call BuildPackage,libffmpeg-custom))
$(eval $(call BuildPackage,libffmpeg-full))
$(eval $(call BuildPackage,libffmpeg-mini))
$(eval $(call BuildPackage,libffmpeg-audio-dec))
