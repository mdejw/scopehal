/***********************************************************************************************************************
*                                                                                                                      *
* libscopeprotocols                                                                                                    *
*                                                                                                                      *
* Copyright (c) 2012-2026 Andrew D. Zonenberg and contributors                                                         *
* All rights reserved.                                                                                                 *
*                                                                                                                      *
* Redistribution and use in source and binary forms, with or without modification, are permitted provided that the     *
* following conditions are met:                                                                                        *
*                                                                                                                      *
*    * Redistributions of source code must retain the above copyright notice, this list of conditions, and the         *
*      following disclaimer.                                                                                           *
*                                                                                                                      *
*    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the       *
*      following disclaimer in the documentation and/or other materials provided with the distribution.                *
*                                                                                                                      *
*    * Neither the name of the author nor the names of any contributors may be used to endorse or promote products     *
*      derived from this software without specific prior written permission.                                           *
*                                                                                                                      *
* THIS SOFTWARE IS PROVIDED BY THE AUTHORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED   *
* TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL *
* THE AUTHORS BE HELD LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES        *
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR       *
* BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT *
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE       *
* POSSIBILITY OF SUCH DAMAGE.                                                                                          *
*                                                                                                                      *
***********************************************************************************************************************/

/**
	@file
	@author Marcin Dawidowicz
	@brief Implementation of EthernetClause73AutonegotiationDecoder
 */

#include "../scopehal/scopehal.h"
#include "EthernetClause73AutonegotiationDecoder.h"

using namespace std;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Construction / destruction

EthernetClause73AutonegotiationDecoder::EthernetClause73AutonegotiationDecoder(const string& color)
	: Filter(color, CAT_SERIAL)
	, m_displayformat("Display Format")
{
	AddProtocolStream("data");
	CreateInput("data");
	CreateInput("clk");

	m_parameters[m_displayformat] = MakeDisplayFormatParameter();
}

FilterParameter EthernetClause73AutonegotiationDecoder::MakeDisplayFormatParameter()
{
	auto f = FilterParameter(FilterParameter::TYPE_ENUM, Unit(Unit::UNIT_COUNTS));
	f.AddEnumValue("Compact", FORMAT_COMPACT);
	f.AddEnumValue("Detailed", FORMAT_DETAILED);
	f.SetIntVal(FORMAT_DETAILED);

	return f;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Factory methods

bool EthernetClause73AutonegotiationDecoder::ValidateChannel(size_t i, StreamDescriptor stream)
{
	if(stream.m_channel == NULL)
		return false;

	if( (i < 2) && (stream.GetType() == Stream::STREAM_TYPE_DIGITAL) )
		return true;

	return false;
}

string EthernetClause73AutonegotiationDecoder::GetProtocolName()
{
	return "Ethernet Clause 73 Autonegotiation";
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Actual decoder logic

static size_t CountConsecutiveBits(const vector<char>& bits, size_t start_idx, int& bit_val)
{
	if(start_idx >= bits.size()) {
		bit_val = 0;
		return 0;
	}

	bit_val = bits[start_idx];
	size_t count = 1;

	for(size_t i = start_idx + 1; i < bits.size(); i++) {
		if(bits[i] == bit_val)
			count++;
		else
			break;
	}

	return count;
}

static vector<char> DecodeAutonegPage(const vector<char>& bits, size_t start_idx, size_t& end_idx)
{
	vector<char> decoded;
	size_t i = start_idx;

	while(i + 1 < bits.size()) {
		int bit1 = bits[i];
		int bit2 = bits[i + 1];

		if(bit1 == bit2) {
			// Same bits - could be 0 or termination
			int bit_val;
			size_t count = CountConsecutiveBits(bits, i, bit_val);

			if(count > 2) {
				// Termination
				end_idx = i;
				return decoded;
			} else {
				// Exactly 2 same bits = 0
				decoded.push_back(0);
				i += 2;
			}
		} else {
			// Different bits (01 or 10) = 1
			decoded.push_back(1);
			i += 2;
		}
	}

	end_idx = i;
	return decoded;
}

static bool ParseCodePage(const vector<char>& bits, Clause73CodePage& page)
{
	if(bits.size() != 49)
		return false;

	// Extract fields (D[0] is LSB - first element in vector)
	// D[4:0] Selector Field
	page.selector_field = 0;
	for(int i = 0; i < 5; i++)
		if(bits[i])
			page.selector_field |= (1ULL << i);

	// D[9:5] Echoed Nonce
	page.echoed_nonce = 0;
	for(int i = 5; i < 10; i++)
		if(bits[i])
			page.echoed_nonce |= (1ULL << (i - 5));

	// D[12:10] Capability
	page.capability = 0;
	for(int i = 10; i < 13; i++)
		if(bits[i])
			page.capability |= (1ULL << (i - 10));

	page.c2_reserved = bits[10];
	page.c1_pause = bits[11];
	page.c0_pause = bits[12];

	// D[15:13] RF/Ack/NP
	page.rf = bits[13];
	page.ack = bits[14];
	page.np = bits[15];

	// D[20:16] Transmitted Nonce
	page.transmitted_nonce = 0;
	for(int i = 16; i < 21; i++)
		if(bits[i])
			page.transmitted_nonce |= (1ULL << (i - 16));

	// D[43:21] Technology Ability
	page.technology_ability = 0;
	for(int i = 21; i < 44; i++)
		if(bits[i])
			page.technology_ability |= (1ULL << (i - 21));

	// D[47:44] Message
	page.message = 0;
	for(int i = 44; i < 48; i++)
		if(bits[i])
			page.message |= (1ULL << (i - 44));

	// D[48] Code
	page.code = bits[48];

	return true;
}

struct StartSequence
{
	size_t start_idx;       // Position after the 8-bit preamble
	bool is_0x0F;           // True if 00001111, false if 11110000
};

static vector<StartSequence> FindAllAutonegStarts(const vector<char>& bits)
{
	vector<StartSequence> starts;

	for(size_t i = 0; i + 8 <= bits.size(); ) {
		// Check for 00001111
		if(bits[i] == 0 && bits[i+1] == 0 && bits[i+2] == 0 && bits[i+3] == 0 &&
			bits[i+4] == 1 && bits[i+5] == 1 && bits[i+6] == 1 && bits[i+7] == 1) {
			starts.push_back({i + 8, true});
			i += 8;
		}
		// Check for 11110000
		else if(bits[i] == 1 && bits[i+1] == 1 && bits[i+2] == 1 && bits[i+3] == 1 &&
				bits[i+4] == 0 && bits[i+5] == 0 && bits[i+6] == 0 && bits[i+7] == 0) {
			starts.push_back({i + 8, false});
			i += 8;
		} else {
			i++;
		}
	}

	return starts;
}

template <std::size_t X>
static std::string FormatBitsX(std::uint64_t val)
{
    static_assert(X > 0, "X must be > 0");
    static_assert(X <= 64, "X must be <= 64 for uint64_t");

    std::array<char, X + 1> buf{}; // +1 for null terminator

    for (std::size_t i = 0; i < X; ++i) {
        buf[X - 1 - i] = (val & (1ULL << i)) ? '1' : '0';
    }
    buf[X] = '\0';

    return std::string(buf.data());
}

void EthernetClause73AutonegotiationDecoder::Refresh()
{
	LogTrace("EthernetClause73AutonegotiationDecoder::Refresh\n");
	LogIndenter li;

	if(!VerifyAllInputsOK()) {
		SetData(nullptr, 0);
		return;
	}

	//Get the input data
	auto din = GetInputWaveform(0);
	auto clkin = GetInputWaveform(1);
	din->PrepareForCpuAccess();
	clkin->PrepareForCpuAccess();

	//Create the capture
	auto cap = new Clause73Waveform(m_parameters[m_displayformat]);
	cap->m_timescale = 1;
	cap->m_startTimestamp = din->m_startTimestamp;
	cap->m_startFemtoseconds = din->m_startFemtoseconds;
	cap->PrepareForCpuAccess();

	//Record the value of the data stream at each clock edge
	SparseDigitalWaveform data;
	SampleOnAnyEdgesBase(din, clkin, data);
	data.PrepareForCpuAccess();

	//Check if we have enough data
	if(data.m_samples.size() < 8) {
		SetData(nullptr, 0);
		return;
	}

	//Convert digital waveform to simple bit vector
	vector<char> bit_stream;
	for(size_t i = 0; i < data.m_samples.size(); i++) {
		bit_stream.push_back(data.m_samples[i]);
	}

	// Find all autonegotiation starts
	vector<StartSequence> start_sequences = FindAllAutonegStarts(bit_stream);

	if(start_sequences.empty()) {
		SetData(nullptr, 0);
		return;
	}

	LogTrace("Found %zu autonegotiation sequences\n", start_sequences.size());

	// Process each sequence
	for(size_t seq_idx = 0; seq_idx < start_sequences.size(); seq_idx++) {
		size_t start_idx = start_sequences[seq_idx].start_idx;
		bool initial_is_0x0F = start_sequences[seq_idx].is_0x0F;

		// Decode the page
		size_t end_idx;
		vector<char> decoded_bits = DecodeAutonegPage(bit_stream, start_idx, end_idx);

		// Only process if we have exactly 49 bits (valid Clause 73 page)
		if(decoded_bits.size() == 49) {
			Clause73CodePage page;
			if(ParseCodePage(decoded_bits, page)) {
				// Store initial start sequence information
				page.initial_start_is_0x0F = initial_is_0x0F;

				// Map the bit position to a timestamp
				// Use the start of the decoded sequence (before preamble) for timing
				size_t preamble_start = start_idx - 8;
				if(preamble_start < data.m_samples.size()) {
					int64_t offset = data.m_offsets[preamble_start];
					int64_t duration = 1; // Default duration

					// Try to get duration from the end index if available
					if(end_idx < data.m_offsets.size() && end_idx > preamble_start) {
						duration = data.m_offsets[end_idx] - data.m_offsets[preamble_start];
					} else if(start_idx + 1 < data.m_durations.size()) {
						duration = data.m_durations[start_idx] * 49; // Approximate
					}

					cap->m_offsets.push_back(offset);
					cap->m_durations.push_back(duration);
					cap->m_samples.push_back(page);
				}
			}
		}
	}

	SetData(cap, 0);
	cap->MarkModifiedFromCpu();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Clause73Waveform

string Clause73Waveform::GetColor(size_t i)
{
	// Color coding based on message type
	const Clause73CodePage& page = m_samples[i];

	// Message field D[47:44] indicates page type
	uint64_t msg = page.message;

	if(msg == 0x1)
		return StandardColors::colors[StandardColors::COLOR_CONTROL];
	else if(msg == 0x2)
		return StandardColors::colors[StandardColors::COLOR_DATA];
	else if(msg == 0x3)
		return StandardColors::colors[StandardColors::COLOR_DATA];
	else if(msg == 0x4)
		return StandardColors::colors[StandardColors::COLOR_CONTROL];
	else
		return StandardColors::colors[StandardColors::COLOR_DATA];
}

string Clause73Waveform::GetText(size_t i)
{
	const Clause73CodePage& page = m_samples[i];

	EthernetClause73AutonegotiationDecoder::DisplayFormat format =
		(EthernetClause73AutonegotiationDecoder::DisplayFormat)m_displayformat.GetIntVal();

	if(format == EthernetClause73AutonegotiationDecoder::FORMAT_COMPACT) {
		// Compact format - single line
		char tmp[512];

		// Get message type from D[47:44]
		uint64_t msg = page.message;

		const char* msg_type = "UNKNOWN";
		switch(msg) {
			case 0x0: msg_type = "Reserved"; break;
			case 0x1: msg_type = "Message Code Page"; break;
			case 0x2: msg_type = "Next Page (Unformatted)"; break;
			case 0x3: msg_type = "Next Page (Msg/Formatted)"; break;
			case 0x4: msg_type = "Previous Page (Unformatted)"; break;
			default: msg_type = "Reserved"; break;
		}

		// // Build initial start sequence indicator
		// string init_str = page.initial_start_is_0x0F ? " [Init: 00001111]" : " [Init: 11110000]";

		snprintf(tmp, sizeof(tmp),
			"Type=\"%s\" Selector = 0x%02lx | Nonce Echoed = 0x%02lx | Nonce Tx = 0x%02lx | Ack=%c | NP=%c | RF=%c | C=%d|%d%d",
			msg_type,
			page.selector_field,
			page.echoed_nonce,
			page.transmitted_nonce,
			page.ack ? '1' : '0',
			page.np ? '1' : '0',
			page.rf ? '1' : '0',
			page.c2_reserved,
			page.c1_pause,
			page.c0_pause
		);

		return string(tmp);
	} else {
		// Detailed format - show all fields with bit positions
		string out;

		// D[4:0] Selector Field
		char tmp[256];
		snprintf(tmp, sizeof(tmp), " D[4:0] Selector: %s(0x%02lx) |",
			FormatBitsX<5>(page.selector_field).c_str(),
			page.selector_field);
		out += tmp;

		// D[9:5] Echoed Nonce
		snprintf(tmp, sizeof(tmp), " D[9:5] Echoed Nonce: %s(0x%02lx) |",
			FormatBitsX<5>(page.echoed_nonce).c_str(),
			page.echoed_nonce);
		out += tmp;

		// D[12:10] Capability
		snprintf(tmp, sizeof(tmp), " D[12:10] Capability: %s |",
			FormatBitsX<3>(page.capability).c_str());
		out += tmp;

		snprintf(tmp, sizeof(tmp), " C[2] Reserved: %d |",
			page.c2_reserved);
		out += tmp;

		snprintf(tmp, sizeof(tmp), " C[1:0] Pause: %d%d(0x%x) |",
			page.c1_pause,
			page.c0_pause,
			(page.c1_pause + 2*page.c0_pause));
		out += tmp;

		// D[15:13] RF/Ack/NP
		snprintf(tmp, sizeof(tmp), " D[15:13] RF/Ack/NP: %d%d%d |",
			page.rf,
			page.ack,
			page.np);
		out += tmp;

		// D[20:16] Transmitted Nonce
		snprintf(tmp, sizeof(tmp), " D[20:16] Tx Nonce: %s(0x%02lx) |",
			FormatBitsX<5>(page.transmitted_nonce).c_str(),
			page.transmitted_nonce);
		out += tmp;

		// D[43:21] Technology Ability
		snprintf(tmp, sizeof(tmp), " D[43:21] Technology Ability: %s |",
			FormatBitsX<23>(page.technology_ability).c_str());
		out += tmp;

		// D[47:44] Message
		snprintf(tmp, sizeof(tmp), " D[47:44] Message: %s(0x%01lx) |",
			FormatBitsX<4>(page.message).c_str(),
			page.message);
		out += tmp;

		// D[48] Code
		snprintf(tmp, sizeof(tmp), " D[48] Code: %d\n",
			page.code);
		out += tmp;

		return out;
	}
}
