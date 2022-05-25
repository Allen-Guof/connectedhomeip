/*
 *   Copyright (c) 2022 Project CHIP Authors
 *   All rights reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */

#include "TraceDecoderProtocolInteractionModel.h"
#include "TraceDecoderToHexString.h"

#include <protocols/interaction_model/Constants.h>

#include <app/MessageDef/InvokeRequestMessage.h>
#include <app/MessageDef/InvokeResponseMessage.h>
#include <app/MessageDef/ReadRequestMessage.h>
#include <app/MessageDef/ReportDataMessage.h>
#include <app/MessageDef/StatusResponseMessage.h>
#include <app/MessageDef/SubscribeRequestMessage.h>
#include <app/MessageDef/SubscribeResponseMessage.h>
#include <app/MessageDef/TimedRequestMessage.h>
#include <app/MessageDef/WriteRequestMessage.h>
#include <app/MessageDef/WriteResponseMessage.h>

#include <lib/support/Base64.h>

#include <app-common/zap-generated/cluster-objects.h>
#include <app-common/zap-generated/ids/Clusters.h>
#include <app-common/zap-generated/ids/Commands.h>

#include <credentials/DeviceAttestationConstructor.h>
#include <credentials/DeviceAttestationVendorReserved.h>

namespace {
constexpr const char * kProtocolName = "Interaction Model";

constexpr const char * kUnknown               = "Unknown";
constexpr const char * kStatusResponse        = "Status Response";
constexpr const char * kReadRequest           = "Read Request";
constexpr const char * kSubscribeRequest      = "Subscribe Request";
constexpr const char * kSubscribeResponse     = "Subscribe Response";
constexpr const char * kReportData            = "Report Data";
constexpr const char * kWriteRequest          = "Write Request";
constexpr const char * kWriteResponse         = "Write Response";
constexpr const char * kInvokeCommandRequest  = "InvokeCommandRequest";
constexpr const char * kInvokeCommandResponse = "InvokeCommandResponse";
constexpr const char * kTimedRequest          = "Timed Request";
} // namespace

using MessageType = chip::Protocols::InteractionModel::MsgType;

namespace chip {
namespace trace {
namespace im {

CHIP_ERROR MaybeDecodeNestedResponseTLV(const uint8_t * data, size_t dataLen);
CHIP_ERROR MaybeDecodeNestedRequestTLV(const uint8_t * data, size_t dataLen);
CHIP_ERROR DecodeStatusResponse(TLV::TLVReader & reader, bool decode);
CHIP_ERROR DecodeReadRequest(TLV::TLVReader & reader, bool decode);
CHIP_ERROR DecodeSubscribeRequest(TLV::TLVReader & reader, bool decode);
CHIP_ERROR DecodeSubscribeResponse(TLV::TLVReader & reader, bool decode);
CHIP_ERROR DecodeReportData(TLV::TLVReader & reader, bool decode);
CHIP_ERROR DecodeWriteRequest(TLV::TLVReader & reader, bool decode);
CHIP_ERROR DecodeWriteResponse(TLV::TLVReader & reader, bool decode);
CHIP_ERROR DecodeInvokeCommandRequest(TLV::TLVReader & reader, bool decode);
CHIP_ERROR DecodeInvokeCommandResponse(TLV::TLVReader & reader, bool decode);
CHIP_ERROR DecodeTimedRequest(TLV::TLVReader & reader, bool decode);

const char * ToProtocolName()
{
    return kProtocolName;
}

const char * ToProtocolMessageTypeName(uint8_t protocolCode)
{
    switch (protocolCode)
    {
    case to_underlying(MessageType::StatusResponse):
        return kStatusResponse;
    case to_underlying(MessageType::ReadRequest):
        return kReadRequest;
    case to_underlying(MessageType::SubscribeRequest):
        return kSubscribeRequest;
    case to_underlying(MessageType::SubscribeResponse):
        return kSubscribeResponse;
    case to_underlying(MessageType::ReportData):
        return kReportData;
    case to_underlying(MessageType::WriteRequest):
        return kWriteRequest;
    case to_underlying(MessageType::WriteResponse):
        return kWriteResponse;
    case to_underlying(MessageType::InvokeCommandRequest):
        return kInvokeCommandRequest;
    case to_underlying(MessageType::InvokeCommandResponse):
        return kInvokeCommandResponse;
    case to_underlying(MessageType::TimedRequest):
        return kTimedRequest;
    default:
        return kUnknown;
    }
}

CHIP_ERROR LogAsProtocolMessage(uint8_t protocolCode, const uint8_t * data, size_t len, bool decodeResponse)
{
    TLV::TLVReader reader;
    reader.Init(data, len);

    switch (protocolCode)
    {
    case to_underlying(MessageType::StatusResponse):
        return DecodeStatusResponse(reader, decodeResponse);
    case to_underlying(MessageType::ReadRequest):
        return DecodeReadRequest(reader, decodeResponse);
    case to_underlying(MessageType::SubscribeRequest):
        return DecodeSubscribeRequest(reader, decodeResponse);
    case to_underlying(MessageType::SubscribeResponse):
        return DecodeSubscribeResponse(reader, decodeResponse);
    case to_underlying(MessageType::ReportData):
        return DecodeReportData(reader, decodeResponse);
    case to_underlying(MessageType::WriteRequest):
        return DecodeWriteRequest(reader, decodeResponse);
    case to_underlying(MessageType::WriteResponse):
        return DecodeWriteResponse(reader, decodeResponse);
    case to_underlying(MessageType::InvokeCommandRequest):
        return DecodeInvokeCommandRequest(reader, decodeResponse);
    case to_underlying(MessageType::InvokeCommandResponse):
        return DecodeInvokeCommandResponse(reader, decodeResponse);
    case to_underlying(MessageType::TimedRequest):
        return DecodeTimedRequest(reader, decodeResponse);
    default:
        return CHIP_ERROR_NOT_IMPLEMENTED;
    }
}

CHIP_ERROR DecodeStatusResponse(TLV::TLVReader & reader, bool decode)
{
    if (decode)
    {
        app::InvokeRequestMessage::Parser parser;
        ReturnErrorOnFailure(parser.Init(reader));
        return parser.CheckSchemaValidity();
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR DecodeReadRequest(TLV::TLVReader & reader, bool decode)
{
    if (decode)
    {
        app::ReadRequestMessage::Parser parser;
        ReturnErrorOnFailure(parser.Init(reader));
        return parser.CheckSchemaValidity();
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR DecodeSubscribeRequest(TLV::TLVReader & reader, bool decode)
{
    if (decode)
    {
        app::SubscribeRequestMessage::Parser parser;
        ReturnErrorOnFailure(parser.Init(reader));
        return parser.CheckSchemaValidity();
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR DecodeSubscribeResponse(TLV::TLVReader & reader, bool decode)
{
    if (decode)
    {
        app::SubscribeResponseMessage::Parser parser;
        ReturnErrorOnFailure(parser.Init(reader));
        return parser.CheckSchemaValidity();
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR DecodeReportData(TLV::TLVReader & reader, bool decode)
{
    if (decode)
    {
        app::ReportDataMessage::Parser parser;
        ReturnErrorOnFailure(parser.Init(reader));
        return parser.CheckSchemaValidity();
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR DecodeWriteRequest(TLV::TLVReader & reader, bool decode)
{
    if (decode)
    {
        app::WriteRequestMessage::Parser parser;
        ReturnErrorOnFailure(parser.Init(reader));
        return parser.CheckSchemaValidity();
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR DecodeWriteResponse(TLV::TLVReader & reader, bool decode)
{
    if (decode)
    {
        app::WriteResponseMessage::Parser parser;
        ReturnErrorOnFailure(parser.Init(reader));
        return parser.CheckSchemaValidity();
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR DecodeInvokeCommandRequest(TLV::TLVReader & reader, bool decode)
{
    const uint8_t * data = reader.GetReadPoint();
    const uint32_t len   = reader.GetTotalLength();
    ReturnErrorOnFailure(MaybeDecodeNestedRequestTLV(data, len));

    if (decode)
    {
        app::InvokeRequestMessage::Parser parser;
        ReturnErrorOnFailure(parser.Init(reader));
        return parser.CheckSchemaValidity();
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR DecodeInvokeCommandResponse(TLV::TLVReader & reader, bool decode)
{
    const uint8_t * data = reader.GetReadPoint();
    const uint32_t len   = reader.GetTotalLength();
    ReturnErrorOnFailure(MaybeDecodeNestedResponseTLV(data, len));

    if (decode)
    {
        app::InvokeResponseMessage::Parser parser;
        ReturnErrorOnFailure(parser.Init(reader));
        return parser.CheckSchemaValidity();
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR DecodeTimedRequest(TLV::TLVReader & reader, bool decode)
{
    if (decode)
    {
        app::TimedRequestMessage::Parser parser;
        ReturnErrorOnFailure(parser.Init(reader));
        return parser.CheckSchemaValidity();
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR LogAttestationResponse(TLV::TLVReader & reader)
{
    ByteSpan attestationElements;
    ByteSpan certificationDeclaration;
    ByteSpan attestationNonce;
    uint32_t timestamp;
    ByteSpan firmwareInfo;
    Credentials::DeviceAttestationVendorReservedDeconstructor vendorReserved;
    char buffer[CHIP_CONFIG_LOG_MESSAGE_MAX_SIZE];

    TLV::TLVType type;
    ReturnErrorOnFailure(reader.EnterContainer(type));
    ReturnErrorOnFailure(reader.Next());
    VerifyOrReturnError(TLV::TagNumFromTag(reader.GetTag()) ==
                            static_cast<uint32_t>(
                                app::Clusters::OperationalCredentials::Commands::AttestationResponse::Fields::kAttestationElements),
                        CHIP_ERROR_INVALID_TLV_TAG);
    ReturnErrorOnFailure(reader.Get(attestationElements));
    ReturnErrorOnFailure(Credentials::DeconstructAttestationElements(attestationElements, certificationDeclaration,
                                                                     attestationNonce, timestamp, firmwareInfo, vendorReserved));
    ReturnErrorOnFailure(reader.ExitContainer(type));

    ChipLogDetail(DataManagement, "Decoded Data (AttestationElements) =");
    ChipLogDetail(DataManagement, "{");
    ChipLogDetail(DataManagement, "    CertificationDeclaration (%zu) = %s", certificationDeclaration.size(),
                  ToHexString(certificationDeclaration, buffer, sizeof(buffer)));
    ChipLogDetail(DataManagement, "    AttestationNonce         (%zu) = %s", attestationNonce.size(),
                  ToHexString(attestationNonce, buffer, sizeof(buffer)));
    ChipLogDetail(DataManagement, "    TimeStamp                      = %u", timestamp);

    if (!firmwareInfo.empty())
    {
        ChipLogDetail(DataManagement, "    FirmwareInfo                 = %s", ToHexString(firmwareInfo, buffer, sizeof(buffer)));
    }

    if (vendorReserved.GetNumberOfElements())
    {
        ChipLogDetail(DataManagement, "    VendorsReserved {");

        Credentials::VendorReservedElement element;
        while (vendorReserved.GetNextVendorReservedElement(element) == CHIP_NO_ERROR)
        {
            ChipLogDetail(DataManagement, "      Vendor {");
            ChipLogDetail(DataManagement, "        vendorId   = %u", element.vendorId);
            ChipLogDetail(DataManagement, "        profileNum = %u", element.profileNum);
            ChipLogDetail(DataManagement, "        data (%zu) = %s", element.vendorReservedData.size(),
                          ToHexString(element.vendorReservedData, buffer, sizeof(buffer)));
            ChipLogDetail(DataManagement, "      }");
        }

        ChipLogDetail(DataManagement, "}");
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR LogCSRResponse(TLV::TLVReader & reader)
{
    ByteSpan nocsrElements;
    ByteSpan csr;
    ByteSpan csrNonce;
    ByteSpan vendorReserved1;
    ByteSpan vendorReserved2;
    ByteSpan vendorReserved3;
    char buffer[CHIP_CONFIG_LOG_MESSAGE_MAX_SIZE];

    TLV::TLVType type;
    ReturnErrorOnFailure(reader.EnterContainer(type));
    ReturnErrorOnFailure(reader.Next());
    VerifyOrReturnError(
        TLV::TagNumFromTag(reader.GetTag()) ==
            static_cast<uint32_t>(app::Clusters::OperationalCredentials::Commands::CSRResponse::Fields::kNOCSRElements),
        CHIP_ERROR_INVALID_TLV_TAG);
    ReturnErrorOnFailure(reader.Get(nocsrElements));
    ReturnErrorOnFailure(
        Credentials::DeconstructNOCSRElements(nocsrElements, csr, csrNonce, vendorReserved1, vendorReserved2, vendorReserved3));
    ReturnErrorOnFailure(reader.ExitContainer(type));

    ChipLogDetail(DataManagement, "Decoded Data (NOCSRElements) =");
    ChipLogDetail(DataManagement, "{");
    ChipLogDetail(DataManagement, "    CSR       (%zu) = %s", csr.size(), ToHexString(csr, buffer, sizeof(buffer)));
    ChipLogDetail(DataManagement, "    CSRNonce  (%zu) = %s", csrNonce.size(), ToHexString(csrNonce, buffer, sizeof(buffer)));

    if (!vendorReserved1.empty())
    {
        ChipLogDetail(DataManagement, "    VendorReserved1 = %s", ToHexString(vendorReserved1, buffer, sizeof(buffer)));
    }

    if (!vendorReserved2.empty())
    {
        ChipLogDetail(DataManagement, "    VendorReserved2 = %s", ToHexString(vendorReserved2, buffer, sizeof(buffer)));
    }

    if (!vendorReserved3.empty())
    {
        ChipLogDetail(DataManagement, "    VendorReserved3 = %s", ToHexString(vendorReserved3, buffer, sizeof(buffer)));
    }

    ChipLogDetail(DataManagement, "}");
    return CHIP_NO_ERROR;
}

CHIP_ERROR LogAddNOC(TLV::TLVReader & reader)
{
    ByteSpan noc;
    ByteSpan icac;
    TLV::TLVType type;

    ReturnErrorOnFailure(reader.EnterContainer(type));
    ReturnErrorOnFailure(reader.Next());
    ReturnErrorOnFailure(reader.Get(noc));

    ReturnErrorOnFailure(reader.Next());
    if (reader.GetTag() ==
        TLV::ContextTag(static_cast<uint8_t>(app::Clusters::OperationalCredentials::Commands::AddNOC::Fields::kICACValue)))
    {
        ReturnErrorOnFailure(reader.Get(icac));
        ReturnErrorOnFailure(reader.Next());
    }

    ReturnErrorOnFailure(reader.ExitContainer(type));

    Platform::ScopedMemoryBuffer<char> nocString;
    nocString.Alloc(BASE64_ENCODED_LEN(noc.size()) + 1);
    auto encodedLen             = Base64Encode(noc.data(), noc.size(), nocString.Get());
    nocString.Get()[encodedLen] = '\0';
    ChipLogDetail(DataManagement, "Decoded Data =");
    ChipLogDetail(DataManagement, "{");
    ChipLogDetail(DataManagement, "    NOCValue  = %s", nocString.Get());

    Platform::ScopedMemoryBuffer<char> icacString;
    icacString.Alloc(BASE64_ENCODED_LEN(icac.size()) + 1);
    encodedLen                   = Base64Encode(icac.data(), icac.size(), icacString.Get());
    icacString.Get()[encodedLen] = '\0';
    ChipLogDetail(DataManagement, "    ICACValue = %s", icacString.Get());
    ChipLogDetail(DataManagement, "}");

    return CHIP_NO_ERROR;
}

CHIP_ERROR LogAddTrustedRootCertificateRequest(TLV::TLVReader & reader)
{
    ByteSpan rcac;

    TLV::TLVType type;
    ReturnErrorOnFailure(reader.EnterContainer(type));
    ReturnErrorOnFailure(reader.Next());
    ReturnErrorOnFailure(reader.Get(rcac));
    ReturnErrorOnFailure(reader.ExitContainer(type));

    Platform::ScopedMemoryBuffer<char> byteString;
    byteString.Alloc(BASE64_ENCODED_LEN(rcac.size()) + 1);
    auto encodedLen              = Base64Encode(rcac.data(), rcac.size(), byteString.Get());
    byteString.Get()[encodedLen] = '\0';

    ChipLogDetail(DataManagement, "Decoded Data =");
    ChipLogDetail(DataManagement, "{");
    ChipLogDetail(DataManagement, "    RootCertificate =  %s", byteString.Get());
    ChipLogDetail(DataManagement, "}");

    return CHIP_NO_ERROR;
}

template <typename T>
bool IsTag(const TLV::TLVReader & reader, T tag)
{
    return to_underlying(tag) == TLV::TagNumFromTag(reader.GetTag());
}

CHIP_ERROR MaybeDecodeCommandData(TLV::TLVReader & reader)
{
    CHIP_ERROR err = CHIP_NO_ERROR;

    ClusterId clusterId;
    CommandId commandId;

    TLV::TLVType containerType;
    while (CHIP_NO_ERROR == (err = reader.Next()))
    {
        if (IsTag(reader, app::CommandDataIB::Tag::kPath))
        {
            ReturnErrorOnFailure(reader.EnterContainer(containerType));
            while (CHIP_NO_ERROR == (err = reader.Next()))
            {
                if (to_underlying(app::CommandPathIB::kCsTag_ClusterId) == TLV::TagNumFromTag(reader.GetTag()))
                {
                    reader.Get(clusterId);
                }
                if (to_underlying(app::CommandPathIB::kCsTag_CommandId) == TLV::TagNumFromTag(reader.GetTag()))
                {
                    reader.Get(commandId);
                }
            }
            ReturnErrorOnFailure(reader.ExitContainer(containerType));
        }

        if (IsTag(reader, app::CommandDataIB::Tag::kData))
        {
            switch (clusterId)
            {
            case app::Clusters::OperationalCredentials::Id:
                switch (commandId)
                {
                case app::Clusters::OperationalCredentials::Commands::AttestationResponse::Id:
                    return LogAttestationResponse(reader);
                case app::Clusters::OperationalCredentials::Commands::CSRResponse::Id:
                    return LogCSRResponse(reader);
                case app::Clusters::OperationalCredentials::Commands::AddNOC::Id:
                    return LogAddNOC(reader);
                case app::Clusters::OperationalCredentials::Commands::AddTrustedRootCertificate::Id:
                    return LogAddTrustedRootCertificateRequest(reader);
                default:
                    return CHIP_NO_ERROR;
                }
                break;
            default:
                break;
            }
        }
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR MaybeDecodeNestedResponseTLV(const uint8_t * data, size_t dataLen)
{
    TLV::TLVReader reader;
    reader.Init(data, dataLen);

    ReturnErrorOnFailure(reader.Next());

    TLV::TLVType containerType;
    ReturnErrorOnFailure(reader.EnterContainer(containerType));

    CHIP_ERROR err = CHIP_NO_ERROR;
    while (CHIP_NO_ERROR == (err = reader.Next()))
    {
        if (IsTag(reader, app::InvokeResponseMessage::Tag::kInvokeResponses))
        {
            ReturnErrorOnFailure(reader.EnterContainer(containerType));
            while (CHIP_NO_ERROR == (err = reader.Next()))
            {
                ReturnErrorOnFailure(reader.EnterContainer(containerType));
                while (CHIP_NO_ERROR == (err = reader.Next()))
                {
                    if (IsTag(reader, app::InvokeResponseIB::Tag::kCommand))
                    {
                        ReturnErrorOnFailure(reader.EnterContainer(containerType));
                        ReturnErrorOnFailure(MaybeDecodeCommandData(reader));
                        ReturnErrorOnFailure(reader.ExitContainer(containerType));
                    }
                }
                ReturnErrorOnFailure(reader.ExitContainer(containerType));
            }
            ReturnErrorOnFailure(reader.ExitContainer(containerType));
        }
    }

    return reader.ExitContainer(containerType);
}

CHIP_ERROR MaybeDecodeNestedRequestTLV(const uint8_t * data, size_t dataLen)
{
    TLV::TLVReader reader;
    reader.Init(data, dataLen);

    ReturnErrorOnFailure(reader.Next());

    TLV::TLVType containerType;
    ReturnErrorOnFailure(reader.EnterContainer(containerType));

    CHIP_ERROR err = CHIP_NO_ERROR;
    while (CHIP_NO_ERROR == (err = reader.Next()))
    {
        if (IsTag(reader, app::InvokeRequestMessage::Tag::kInvokeRequests))
        {
            ReturnErrorOnFailure(reader.EnterContainer(containerType));
            while (CHIP_NO_ERROR == (err = reader.Next()))
            {
                ReturnErrorOnFailure(reader.EnterContainer(containerType));
                ReturnErrorOnFailure(MaybeDecodeCommandData(reader));
                ReturnErrorOnFailure(reader.ExitContainer(containerType));
            }
            ReturnErrorOnFailure(reader.ExitContainer(containerType));
        }
    }

    return reader.ExitContainer(containerType);
}

} // namespace im
} // namespace trace
} // namespace chip
